-- PEI-1407: the managed console presents GXWI's public certificate identity
-- before collecting a username. Authentication is not involved in this test.
local peinit = require("helpers.peinit")
peinit.claim(2)

local digest = string.rep("AB:", 31) .. "AB"

local function boot(name, fingerprint)
    local files = peinit.seed("pt-login-browser", {
        { path = [[Machine\Software]] },
        { path = [[Machine\Software\GXWI]], values = {
            { name = "Listen", type = "sz", data = "192.0.2.8:8443" },
        } },
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- Keep the fixed public fingerprint fixture from being replaced.
        { path = [[Machine\System\Services\gxwid]], values = {
            { name = "Conditions", type = "multi", data = { "path:/pt-no-gxwid" } },
        } },
        { path = [[Machine\System\Services\login-console]], values = {
            { name = "Arguments", type = "multi", data = { "--console" } },
        } },
    })
    files["var/state/gxwi/certificate.sha256"] = fingerprint
    local vm = peinit.boot({ name = name, files = files })
    wait_until(function()
        return vm:console():read_log():find("Username:", 1, true) ~= nil
    end, { timeout = 60, interval = 0.1, desc = "the username prompt" })
    return vm
end

test("the local console shows the configured GXWI URL and SHA-256 before username input",
    { tags = { "pei1407" } }, function(t)
        local vm = boot("login-browser", digest .. "\n")
        local log = vm:console():read_log()
        local url = log:find("login: GXWI: https://192.0.2.8:8443/", 1, true)
        local fingerprint = log:find("login: GXWI certificate SHA-256: " .. digest, 1, true)
        local prompt = log:find("Username:", 1, true)
        t:assert(url and fingerprint and prompt and url < prompt and fingerprint < prompt,
            "browser address and exact fingerprint precede the username prompt")
    end)

test("an invalid GXWI fingerprint is not rendered and does not block console login",
    { tags = { "pei1407" } }, function(t)
        local vm = boot("login-bad-fingerprint", digest .. "\27[2J")
        local log = vm:console():read_log()
        t:assert(log:find("login: GXWI certificate fingerprint unavailable.", 1, true),
            "invalid public file is reported as unavailable")
        t:assert(not log:find(digest, 1, true), "the unvalidated fingerprint is not printed")
        t:assert(log:find("Username:", 1, true), "authentication can still begin")
    end)
