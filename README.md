# Row Level Security Escape Hatches

Six proof-of-concept requests against **SERVI**'s production Supabase
project — a mobile service-booking app (Expo/React Native) with no custom
backend: every table is reachable directly from the client through
PostgREST, so Row Level Security policies are the **entire** authorization
boundary. Each PoC is a normal, authenticated API call a real client could
make; none of them touch an admin/service-role key. All six are patched as
of this write-up.

| # | Severity | Finding | Status |
|---|---|---|---|
| [POC-1](#poc-1--self-role-escalation-via-profilesrole) | **Critical** | Self role escalation via `profiles.role` | Fixed |
| [POC-2](#poc-2--customer-self-confirms-their-own-booking) | High | Customer self-confirms their own booking | Fixed |
| [POC-3](#poc-3--booking-price-forgery-via-booking_services) | High | Booking price forgery via `booking_services` | Fixed |
| [POC-4](#poc-4--review-posted-against-a-never-completed-booking) | Medium | Review posted against a never-completed booking | Fixed |
| [POC-5](#poc-5--system-wide-cron-function-callable-by-anon) | Medium | System-wide cron function callable by `anon` | Fixed |
| [POC-6](#poc-6--conversation-hijack-via-participant-reassignment) | Medium | Conversation hijack via participant reassignment | Fixed |

## Why this class of bug exists

An architecture with no application server in front of Postgres is
completely valid — but it raises the stakes on every single RLS policy: a
gap here isn't "one more layer to defend," it's the whole wall. Postgres
RLS's `USING` clause governs which rows are *visible*; `WITH CHECK` governs
what the *new* row may look like. Skip `WITH CHECK` on an UPDATE policy and
Postgres silently reuses `USING` for it — which only re-confirms "is this
still my row," never "did I only change the columns the UI meant to
expose." Every finding below is a variation on that one gap.

## Reproducing these without a real device or JWT

Every payload below runs as plain SQL against the database, wrapped in
`begin; ... rollback;` so nothing persists. The two lines that matter:

```sql
set local role authenticated;
set local request.jwt.claim.sub = '<uuid>';
```

Supabase's `auth.uid()` is just:

```sql
select coalesce(
  nullif(current_setting('request.jwt.claim.sub', true), ''),
  (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
)::uuid
```

— so setting that GUC directly simulates exactly what PostgREST sets from a
real user's JWT. No token, no client, no real device needed to test any
Supabase RLS policy this way.

---

## POC-1 — Self role escalation via `profiles.role`

**Severity: Critical**

`profiles`'s UPDATE policy checked only `auth.uid() = id` — no `WITH CHECK`
at all. Nothing stopped a customer account from setting its own `role`
straight to `'business'`, gaining a full business dashboard with no approval
step, fully reversible back to `'customer'` the same way.

**Vulnerable policy (before):**

```sql
create policy "profiles are updatable by their owner"
  on profiles for update
  using (auth.uid() = id);
  -- no WITH CHECK — any column, including role, was fair game
```

**Payload — run as the victim's own session:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

update profiles set role = 'business' where id = '<my-own-customer-uuid>';
-- pre-fix: 1 row updated. next app load routes into the business tree.
```

**Post-fix result — captured against the live database:**

```
ERROR:  P0001: role cannot be changed after signup
CONTEXT:  PL/pgSQL function prevent_role_change() line 4 at RAISE
```

**Fix:** a `BEFORE UPDATE` trigger that compares `NEW.role` against
`OLD.role` directly — something a bare RLS policy can't do, since
`WITH CHECK` only ever sees the incoming row:

```sql
create function prevent_role_change()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.role is distinct from old.role then
    raise exception 'role cannot be changed after signup';
  end if;
  return new;
end;
$$;

create trigger lock_profile_role
  before update on profiles
  for each row execute procedure prevent_role_change();
```

---

## POC-2 — Customer self-confirms their own booking

**Severity: High**

The `bookings` UPDATE policy let the owning customer touch *any* column on
their own row, not just `start_time`/`status` the reschedule/cancel screens
actually send. That includes `status` itself — a customer could jump their
own booking straight to `'confirmed'` or `'completed'`, skipping the
business's real confirmation and firing the same server-side notification
triggers a legitimate confirmation would.

**Payload:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

update bookings set status = 'confirmed' where id = '<my-own-completed-booking>';
```

**Post-fix result — captured against the live database:**

```
ERROR:  P0001: customers may only set booking status to pending or cancelled
CONTEXT:  PL/pgSQL function enforce_booking_update_rules() line 26 at RAISE
```

**Control — the legitimate reschedule shape still works, unmodified:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

update bookings set start_time = now() + interval '3 days', status = 'pending'
where id = '<my-own-booking>';
-- result: status | pending, start_time | (new value) — succeeds
```

**Fix:** a role-aware `BEFORE UPDATE` trigger that pins every immutable
column (`customer_id`, `business_id`, `service_id`, `staff_id`,
`total_price`, `total_duration_minutes`) and only lets the customer's own
status land on `pending`/`cancelled` — `confirmed`/`completed` is
business-only, matching exactly what the app's own mutations do, nothing
more.

---

## POC-3 — Booking price forgery via `booking_services`

**Severity: High**

Booking creation inserted `price` and `duration_minutes` straight from
client state — the INSERT policy checked only that the caller owned the
parent booking, never that the price actually matched the referenced
service. A modified client could book any real service at any price,
including a fraction of a cent.

**Payload — the service's real price is 40.00 / 45 min:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

insert into booking_services (booking_id, service_id, price, duration_minutes, position)
values ('<my-booking>', '<real-service-id>', 0.01, 99999, 0)
returning price, duration_minutes;
```

**Post-fix result — captured against the live database:**

```sql
-- row inserted (RLS doesn't reject it — the INSERT is legitimately owned),
-- but the total tells the real story:
select total_price, total_duration_minutes from bookings where id = '<my-booking>';
--> total_price: 80.00, total_duration_minutes: 90
-- (this booking's original total was 40.00 / 45 — the new row was
-- silently corrected to the SAME real service price/duration, not the
-- 0.01 / 99999 the payload sent)
```

**Fix:** a `BEFORE INSERT` trigger on `booking_services` re-derives
price/duration from the real `services`/`packages` rows, discarding
whatever the client sent; an `AFTER INSERT` trigger then resyncs
`bookings.total_price`/`total_duration_minutes` from the true sum. No
client code had to change — the numbers it sends just stopped being
trusted.

---

## POC-4 — Review posted against a never-completed booking

**Severity: Medium**

The review form only renders client-side for `status = 'completed'`
bookings — the INSERT policy never checked status at all, so a review could
be attached to a booking that was merely `pending` or even `cancelled`.

**Payload — against a booking with `status = 'cancelled'`:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

insert into reviews (booking_id, customer_id, business_id, rating, comment)
values ('<cancelled-booking>', '<my-uuid>', '<business-id>', 5, 'never happened');
```

**Post-fix result — captured against the live database:**

```
ERROR:  42501: new row violates row-level security policy for table "reviews"
```

**Fix:** the INSERT policy now joins back to `bookings` and requires
`status = 'completed'`, matching what the UI already assumed.

---

## POC-5 — System-wide cron function callable by `anon`

**Severity: Medium**

`send_booking_reminders()` loops over every business's upcoming bookings and
messages customers — meant to run only from `pg_cron`. It was explicitly
granted to `authenticated` "for testing," but that grant was already
redundant: Postgres grants `EXECUTE` to `PUBLIC` by default on function
creation, and Supabase layers its own default grant to
`anon`/`authenticated` on top of that — independently of each other. Three
separate things had to be revoked, not one.

**Checking who could actually call it** (a straight privilege check, no
session simulation needed):

```sql
select has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can_exec,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_can_exec
from pg_proc p where p.proname = 'send_booking_reminders';

--> anon_can_exec: true, authenticated_can_exec: true
```

**First revoke attempt — incomplete:**

```sql
revoke execute on function send_booking_reminders() from authenticated;
-- re-checked: anon_can_exec was STILL true — the PUBLIC default grant
-- and Supabase's own anon default grant are each independent of the
-- authenticated-specific revoke above.
```

**Actual fix — all three explicitly:**

```sql
revoke execute on function send_booking_reminders() from public;
revoke execute on function send_booking_reminders() from anon;
revoke execute on function send_booking_reminders() from authenticated;

-- re-checked: anon_can_exec: false, authenticated_can_exec: false,
--             postgres_can_exec: true, service_role_can_exec: true
```

pg_cron keeps working unaffected — the function owner (`postgres`, who ran
`cron.schedule`) always retains implicit `EXECUTE` regardless of grants to
other roles.

---

## POC-6 — Conversation hijack via participant reassignment

**Severity: Medium**

Same shape as POC-1/2, smaller blast radius. A conversation participant
legitimately updating their own read-receipt timestamp could, in principle,
also rewrite `customer_id` or `business_id` on that row — and even giving
the update policy a matching `WITH CHECK` doesn't close this, since a
business owner keeping their own `business_id` unchanged still passes the
ownership check no matter what they set `customer_id` to:

```sql
with check (
  auth.uid() = customer_id
  or exists (select 1 from businesses where businesses.id = conversations.business_id
             and businesses.owner_id = auth.uid())
)
-- a business owner setting customer_id to ANY other uuid still passes —
-- the second branch only checks business_id, which they didn't touch
```

**Actual fix — a trigger, not another RLS clause:**

```sql
create function lock_conversation_participants()
returns trigger language plpgsql as $$
begin
  if new.customer_id is distinct from old.customer_id
    or new.business_id is distinct from old.business_id then
    raise exception 'conversation participants cannot be changed after creation';
  end if;
  return new;
end; $$;
```

---

## The one-line takeaway

For anyone auditing their own Supabase schema: grep every `for update` or
`for all` policy for a missing `with check` — that's POC-1, 2, and 6 here.
Then ask, for every INSERT policy, whether it checks *who* is inserting
without checking whether the *values* they're inserting are true (POC-3).
Then check every `grant execute` against
`has_function_privilege('anon', ...)` directly rather than trusting the
grant statement you wrote — Postgres and Supabase both layer default
privileges you didn't ask for (POC-5).

The recurring lesson across all six: RLS policies see either the old row
(`USING`) or the new row (`WITH CHECK`), never both at once — a trigger is
the only construct that can actually compare them.

---

*All six PoCs were run against SERVI's own development database via direct
SQL, simulating an authenticated session with `set local role` +
`request.jwt.claim.sub` — no production data, no third-party target, no
credentials beyond the tester's own account. Every fix shown is live in the
schema as of this write-up.*
