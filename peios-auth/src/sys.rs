//! Generated private declarations; use the safe wrapper.
use auth_abi::*;
pub enum Client {}
pub enum Operation {}
#[link(name = "auth")]
unsafe extern "C" {
    pub fn peios_auth_abi_version() -> u32;
    pub fn peios_auth_client_create(options: *const ClientOptions) -> *mut Client;
    pub fn peios_auth_client_destroy(client: *mut Client) -> ();
    pub fn peios_auth_logon_begin(
        client: *const Client,
        request: *const LogonRequest,
    ) -> *mut Operation;
    pub fn peios_auth_service_attest_begin(
        client: *const Client,
        request: *const ServiceRequest,
    ) -> *mut Operation;
    pub fn peios_auth_password_change_begin(
        client: *const Client,
        supported_credentials: u32,
    ) -> *mut Operation;
    pub fn peios_auth_key_add_begin(
        client: *const Client,
        public_key: Bytes,
        supported_credentials: u32,
    ) -> *mut Operation;
    pub fn peios_auth_key_remove_begin(
        client: *const Client,
        fingerprint: Bytes,
        supported_credentials: u32,
    ) -> *mut Operation;
    pub fn peios_auth_identity_lookup_begin(
        client: *const Client,
        request: *const LookupRequest,
    ) -> *mut Operation;
    pub fn peios_auth_identity_enumerate_begin(
        client: *const Client,
        request: *const EnumerateRequest,
    ) -> *mut Operation;
    pub fn peios_auth_account_self_begin(client: *const Client) -> *mut Operation;
    pub fn peios_auth_display_name_set_begin(client: *const Client, name: Bytes) -> *mut Operation;
    pub fn peios_auth_session_end_query_begin(
        client: *const Client,
        session_id: u64,
    ) -> *mut Operation;
    pub fn peios_auth_session_end_begin(client: *const Client, session_id: u64) -> *mut Operation;
    pub fn peios_auth_operation_step(operation: *mut Operation) -> i32;
    pub fn peios_auth_operation_poll_info(operation: *const Operation, out: *mut PollInfo) -> i32;
    pub fn peios_auth_operation_wait(operation: *mut Operation) -> i32;
    pub fn peios_auth_operation_respond(
        operation: *mut Operation,
        round: u64,
        answers: *const Answer,
        count: usize,
    ) -> i32;
    pub fn peios_auth_operation_cancel(operation: *mut Operation) -> ();
    pub fn peios_auth_operation_destroy(operation: *mut Operation) -> ();
    pub fn peios_auth_operation_error(operation: *const Operation, out: *mut ErrorView) -> i32;
    pub fn peios_auth_operation_round(
        operation: *const Operation,
        round: *mut u64,
        messages: *mut usize,
        prompts: *mut usize,
    ) -> i32;
    pub fn peios_auth_operation_prompt(
        operation: *const Operation,
        index: usize,
        out: *mut PromptView,
    ) -> i32;
    pub fn peios_auth_operation_message(
        operation: *const Operation,
        index: usize,
        out: *mut MessageView,
    ) -> i32;
    pub fn peios_auth_operation_grant(operation: *const Operation, out: *mut GrantView) -> i32;
    pub fn peios_auth_operation_take_token(operation: *mut Operation) -> i32;
    pub fn peios_auth_operation_ended(operation: *const Operation, out: *mut EndedView) -> i32;
    pub fn peios_auth_operation_identity(
        operation: *const Operation,
        out: *mut IdentityView,
    ) -> i32;
    pub fn peios_auth_operation_incomplete_source(
        operation: *const Operation,
        index: usize,
        out: *mut Bytes,
    ) -> i32;
    pub fn peios_auth_record(
        operation: *const Operation,
        index: usize,
        out: *mut RecordView,
    ) -> i32;
    pub fn peios_auth_record_field_state(
        operation: *const Operation,
        index: usize,
        field: u32,
    ) -> i32;
    pub fn peios_auth_record_text(
        operation: *const Operation,
        index: usize,
        field: u32,
        out: *mut Bytes,
    ) -> i32;
    pub fn peios_auth_record_number(
        operation: *const Operation,
        index: usize,
        field: u32,
        out: *mut u32,
    ) -> i32;
    pub fn peios_auth_record_reference_count(
        operation: *const Operation,
        index: usize,
        field: u32,
        out: *mut usize,
    ) -> i32;
    pub fn peios_auth_record_reference(
        operation: *const Operation,
        index: usize,
        field: u32,
        item: usize,
        out: *mut ReferenceView,
    ) -> i32;
    pub fn peios_auth_record_claim_count(
        operation: *const Operation,
        index: usize,
        out: *mut usize,
    ) -> i32;
    pub fn peios_auth_record_claim(
        operation: *const Operation,
        index: usize,
        item: usize,
        out: *mut ClaimView,
    ) -> i32;
    pub fn peios_auth_record_claim_value(
        operation: *const Operation,
        index: usize,
        item: usize,
        value: usize,
        out: *mut ClaimValue,
    ) -> i32;
    pub fn peios_auth_operation_account(operation: *const Operation, out: *mut AccountView) -> i32;
    pub fn peios_auth_operation_account_key(
        operation: *const Operation,
        index: usize,
        out: *mut AccountKeyView,
    ) -> i32;
}
