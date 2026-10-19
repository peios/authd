-- authd and lpsd as emitters (PEI-617): the events each writes about what
-- it did, read back out of the event store as an administrator would.
--
-- authd.evman and lpsd.evman, shipped by dev.peios.authd and
-- dev.peios.authd-lpsd into /usr/share/evman, are the catalogue's word on
-- every type and field asserted here.
--
-- One file-scope VM: the peinit profile boots the whole edition, which
-- runs authd, lpsd and eventd, and ships `lps`, `login` and `logonse`.
-- The agent is SYSTEM, which may originate any logon type and administer
-- lpsd, so every request below is the agent's own and every record names
-- SYSTEM as whoever asked.
--
-- A SID in a record is `bin.sid`; evctl's JSON renders a binary value as
-- {"$binary": "<hex>"}, which is what the constants below are.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
peinit.claim(1)

local SYSTEM = "010100000000000512000000"          -- S-1-5-18
local LOCAL_SERVICE = "010100000000000513000000"   -- S-1-5-19
local ADMINISTRATORS = "01020000000000052000000020020000" -- S-1-5-32-544

local function on_demand(name, identity)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = identity },
    } }
end

local vm = eventd.boot({
    name = "authd-events",
    files = peinit.seed("pt-authd-events", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        on_demand("pt-attest-local", "LocalService"),
        on_demand("pt-attest-stranger", "pt-nobody"),
    }),
})

local function hex(value)
    return type(value) == "table" and value["$binary"] or nil
end

--- Wait for a row of `query` satisfying `pred`, and return it.
local function find(query, pred, desc)
    local rows = eventd.wait_rows(vm, query, function(rows)
        for _, row in ipairs(rows) do
            if pred(row) then return true end
        end
        return false
    end, { desc = desc })
    for _, row in ipairs(rows) do
        if pred(row) then return row end
    end
end

test("a service the authority attests is recorded with the identity it got", function(t)
    vm:run("svctl start pt-attest-local")
    local row = find("EVENTS authd.service.attested SINCE 1h ago TAKE 1000 SELECT "
            .. "object.service.name, object.token.sid, subject.token.sid, outcome.success, "
            .. "object.session.id",
        function(row) return row["object.service.name"] == "pt-attest-local" end,
        "authd.service.attested for pt-attest-local")
    t:assert_eq(row["outcome.success"], true, "the attestation succeeded")
    t:assert_eq(hex(row["object.token.sid"]), LOCAL_SERVICE, "as LocalService")
    t:assert_eq(hex(row["subject.token.sid"]), SYSTEM,
        "asked for by the service manager, which is SYSTEM")
    t:assert(type(row["object.session.id"]) == "number", "naming the session it created")
end)

test("a refused attestation is recorded with the denial", function(t)
    vm:run("svctl start pt-attest-stranger")
    local row = find("EVENTS authd.service.attested SINCE 1h ago TAKE 1000 SELECT "
            .. "object.service.name, object.token.sid, outcome.success, outcome.reason",
        function(row) return row["object.service.name"] == "pt-attest-stranger" end,
        "authd.service.attested for pt-attest-stranger")
    t:assert_eq(row["outcome.success"], false, "the attestation was refused")
    t:assert_eq(row["outcome.reason"], "account-restricted",
        "because no source holds an identity designated for service logon by that name")
    t:assert(row["object.token.sid"] == nil, "and no token was minted to name")
end)

test("an administrator's account and group changes are recorded by SID", function(t)
    -- The edition provisions its live account with `lps add` at first boot,
    -- and a record names no account by name, so this test's account is the
    -- one created after the accounts already recorded.
    local before = {}
    for _, row in ipairs(eventd.rows(vm, "EVENTS lpsd.account.created SINCE 1h ago "
            .. "TAKE 1000 SELECT object.account.sid")) do
        local sid = hex(row["object.account.sid"])
        if sid then before[sid] = true end
    end

    vm:run("lps add pt-audit-user --no-password --no-prompt"):assert_ok()
    local created = find("EVENTS lpsd.account.created SINCE 1h ago TAKE 1000 SELECT "
            .. "subject.token.sid, object.account.sid, outcome.success",
        function(row)
            local sid = hex(row["object.account.sid"])
            return row["outcome.success"] == true and sid ~= nil and not before[sid]
        end,
        "lpsd.account.created for pt-audit-user")
    local account = hex(created["object.account.sid"])
    t:assert_eq(hex(created["subject.token.sid"]), SYSTEM, "the administrator who asked")

    vm:run("lps group add pt-audit-user Administrators"):assert_ok()
    local added = find("EVENTS lpsd.group.member.added SINCE 1h ago TAKE 1000 SELECT "
            .. "object.account.sid, object.group.sid, outcome.success",
        function(row) return hex(row["object.account.sid"]) == account end,
        "lpsd.group.member.added for the new account")
    t:assert_eq(hex(added["object.group.sid"]), ADMINISTRATORS,
        "a well-known group is named by its SID")
    t:assert_eq(added["outcome.success"], true)

    vm:run("lps remove pt-audit-user"):assert_ok()
    local deleted = find("EVENTS lpsd.account.deleted SINCE 1h ago TAKE 1000 SELECT "
            .. "object.account.sid, outcome.success",
        function(row) return hex(row["object.account.sid"]) == account end,
        "lpsd.account.deleted for the account")
    t:assert_eq(deleted["outcome.success"], true,
        "the deletion names the SID the account had, read before it went")
end)

test("a refused administrative change is recorded with the failure lps was told", function(t)
    local r = vm:run("lps remove pt-audit-nobody")
    t:assert(r.exit_code ~= 0, "lps reported the failure")
    local row = find("EVENTS lpsd.account.deleted SINCE 1h ago TAKE 1000 SELECT "
            .. "object.account.sid, outcome.success, outcome.reason",
        function(row) return row["outcome.success"] == false end,
        "a failed lpsd.account.deleted")
    t:assert_eq(row["outcome.reason"], "not-found")
    t:assert(row["object.account.sid"] == nil, "there was no account to name")
end)

test("a logon is recorded from both sides, and its session's end with who asked", function(t)
    vm:run("lps add pt-audit-kiosk --no-password --no-prompt"):assert_ok()
    -- The kiosk's shell reads a pipe that a background sleep holds open, so
    -- the session stays alive long enough to be ended by request.
    vm:run("( sleep 60 | login --try-no-password pt-audit-kiosk -h 192.0.2.7 )"
        .. " >/dev/null 2>&1 &")

    local logon = find("EVENTS authd.logon.attempted SINCE 1h ago TAKE 1000 SELECT "
            .. "source.token.sid, source.address, subject.token.sid, object.session.id, "
            .. "object.session.logon-type, object.session.auth-package, outcome.success",
        function(row)
            return row["outcome.success"] == true and row["source.address"] == "192.0.2.7"
        end,
        "a successful authd.logon.attempted from the kiosk login")
    t:assert_eq(hex(logon["source.token.sid"]), SYSTEM, "the originator is login, as SYSTEM")
    t:assert_eq(logon["object.session.logon-type"], "interactive")
    t:assert_eq(logon["object.session.auth-package"], "lpsd")
    local kiosk = hex(logon["subject.token.sid"])
    t:assert(kiosk and kiosk ~= SYSTEM, "the principal signed in is the kiosk account")
    local session = logon["object.session.id"]
    t:assert(type(session) == "number", "and the session is named")

    local verified = find("EVENTS lpsd.credential.verified SINCE 1h ago TAKE 1000 SELECT "
            .. "object.account.sid, operation.name, outcome.success",
        function(row) return hex(row["object.account.sid"]) == kiosk end,
        "lpsd.credential.verified for the kiosk account")
    t:assert_eq(verified["operation.name"], "none", "a passwordless account checks nothing")
    t:assert_eq(verified["outcome.success"], true)

    vm:run("logonse end " .. string.format("%d", session)):assert_ok()
    local ended = find("EVENTS authd.session.ended SINCE 1h ago TAKE 1000 SELECT "
            .. "subject.token.sid, object.session.id, object.session.user.sid, outcome.success",
        function(row) return row["object.session.id"] == session end,
        "authd.session.ended for the kiosk session")
    t:assert_eq(hex(ended["subject.token.sid"]), SYSTEM, "who asked")
    t:assert_eq(hex(ended["object.session.user.sid"]), kiosk, "whose session it was")
    t:assert_eq(ended["outcome.success"], true, "nothing was left holding it")
end)

test("a failed logon is recorded and the name tried is not", function(t)
    -- No account by this name, and no credential type offered: the source
    -- refuses without prompting, and login's fallback finds no terminal.
    vm:run("timeout 10 login --try-no-password pt-audit-unknown -h 192.0.2.8 </dev/null"
        .. " >/dev/null 2>&1")
    local row = find("EVENTS authd.logon.attempted SINCE 1h ago TAKE 1000 SELECT "
            .. "source.address, subject.token.sid, outcome.success, outcome.reason",
        function(row) return row["source.address"] == "192.0.2.8" end,
        "a failed authd.logon.attempted")
    t:assert_eq(row["outcome.success"], false)
    t:assert_eq(row["outcome.reason"], "authentication-failed")
    t:assert(row["subject.token.sid"] == nil, "nobody was signed in to name")

    local all = eventd.query(vm, "EVENTS authd.* SINCE 1h ago TAKE 10000")
    t:assert(all.ok, "authd's records are readable")
    t:assert(not all.stdout:find("pt-audit-unknown", 1, true),
        "no record of authd's carries the name that was tried")
    local lpsd = eventd.query(vm, "EVENTS lpsd.* SINCE 1h ago TAKE 10000")
    t:assert(lpsd.ok, "lpsd's records are readable")
    t:assert(not lpsd.stdout:find("pt-audit", 1, true),
        "nor does any of lpsd's carry an account name")
end)
