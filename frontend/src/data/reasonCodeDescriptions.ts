export interface ReasonCodeMeta {
  code: string;
  category: string;
  plainDescription: string;
  typicalAction: 'ALLOW' | 'ASK' | 'BLOCK' | 'MIXED';
}

export const REASON_CODE_CATEGORIES = [
  'Argument Validation',
  'Policy & Constraints',
  'Taint & Data Flow',
  'Approval Flow',
  'Output Inspection',
  'System & Session State',
] as const;

export const REASON_CODE_METADATA: Record<string, ReasonCodeMeta> = {
  ACCOUNT_NOT_ALLOWED: {
    code: 'ACCOUNT_NOT_ALLOWED',
    category: 'Policy & Constraints',
    plainDescription: 'The target account identifier is not permitted under current policy constraints.',
    typicalAction: 'BLOCK',
  },
  ALL_RULES_PASSED: {
    code: 'ALL_RULES_PASSED',
    category: 'Policy & Constraints',
    plainDescription: 'All policy checks and validation rules succeeded with no violations found.',
    typicalAction: 'ALLOW',
  },
  ALWAYS_ASK_TOOL: {
    code: 'ALWAYS_ASK_TOOL',
    category: 'Approval Flow',
    plainDescription: 'The invoked tool is marked as high-impact and unconditionally requires human review.',
    typicalAction: 'ASK',
  },
  AMOUNT_OVER_LIMIT: {
    code: 'AMOUNT_OVER_LIMIT',
    category: 'Policy & Constraints',
    plainDescription: 'The requested monetary or numeric amount exceeds policy limits.',
    typicalAction: 'BLOCK',
  },
  APPROVAL_CALLBACK_ERROR: {
    code: 'APPROVAL_CALLBACK_ERROR',
    category: 'Approval Flow',
    plainDescription: 'An internal error occurred during the human approval callback execution.',
    typicalAction: 'BLOCK',
  },
  APPROVAL_TIMEOUT: {
    code: 'APPROVAL_TIMEOUT',
    category: 'Approval Flow',
    plainDescription: 'Human approval was requested but timed out without a decision (fail-closed).',
    typicalAction: 'BLOCK',
  },
  ARG_FROM_UNTRUSTED_UNFLAGGED: {
    code: 'ARG_FROM_UNTRUSTED_UNFLAGGED',
    category: 'Taint & Data Flow',
    plainDescription: 'An argument originated from untrusted input but has not triggered a specific rule.',
    typicalAction: 'MIXED',
  },
  ARG_MATCHES_HIGH_SUSPICION_SEGMENT: {
    code: 'ARG_MATCHES_HIGH_SUSPICION_SEGMENT',
    category: 'Taint & Data Flow',
    plainDescription: 'An argument value was traced directly to input text flagged with high suspicion of injection.',
    typicalAction: 'BLOCK',
  },
  ARG_MATCHES_MEDIUM_SUSPICION_SEGMENT: {
    code: 'ARG_MATCHES_MEDIUM_SUSPICION_SEGMENT',
    category: 'Taint & Data Flow',
    plainDescription: 'An argument value was traced to input text flagged with medium suspicion of injection.',
    typicalAction: 'ASK',
  },
  ARG_MATCHES_UNREVIEWED_SEGMENT: {
    code: 'ARG_MATCHES_UNREVIEWED_SEGMENT',
    category: 'Taint & Data Flow',
    plainDescription: 'An argument was derived from unreviewed text segments that have not passed scan validation.',
    typicalAction: 'ASK',
  },
  AUDIT_EVENT_REJECTED: {
    code: 'AUDIT_EVENT_REJECTED',
    category: 'System & Session State',
    plainDescription: 'The audit store rejected recording this event due to schema or constraint mismatch.',
    typicalAction: 'BLOCK',
  },
  AUDIT_UNAVAILABLE: {
    code: 'AUDIT_UNAVAILABLE',
    category: 'System & Session State',
    plainDescription: 'The audit store is unreachable or unavailable; operations fail closed.',
    typicalAction: 'BLOCK',
  },
  CONFIDENTIAL_DATA_EXTERNAL: {
    code: 'CONFIDENTIAL_DATA_EXTERNAL',
    category: 'Taint & Data Flow',
    plainDescription: 'Sensitive or confidential data was detected in arguments bound for an external service.',
    typicalAction: 'BLOCK',
  },
  CONSTRAINT_VIOLATION: {
    code: 'CONSTRAINT_VIOLATION',
    category: 'Policy & Constraints',
    plainDescription: 'A custom policy constraint was violated by the requested action.',
    typicalAction: 'BLOCK',
  },
  DOMAIN_NOT_ALLOWED: {
    code: 'DOMAIN_NOT_ALLOWED',
    category: 'Policy & Constraints',
    plainDescription: 'The destination domain is not on the policy whitelist.',
    typicalAction: 'BLOCK',
  },
  INTENT_MATCHES_FLAGGED_SEGMENT: {
    code: 'INTENT_MATCHES_FLAGGED_SEGMENT',
    category: 'Taint & Data Flow',
    plainDescription: 'The inferred intent of the tool call aligns with an attacker instruction segment.',
    typicalAction: 'BLOCK',
  },
  INTERNAL_ERROR: {
    code: 'INTERNAL_ERROR',
    category: 'System & Session State',
    plainDescription: 'An unhandled exception occurred within the firewall core (fail-closed).',
    typicalAction: 'BLOCK',
  },
  INVALID_ARGUMENT_VALUE: {
    code: 'INVALID_ARGUMENT_VALUE',
    category: 'Argument Validation',
    plainDescription: 'The argument value violates expected schema formatting or range constraints.',
    typicalAction: 'BLOCK',
  },
  JUDGE_UNAVAILABLE: {
    code: 'JUDGE_UNAVAILABLE',
    category: 'System & Session State',
    plainDescription: 'The Layer 1 judge service was unavailable when required to inspect input.',
    typicalAction: 'BLOCK',
  },
  LINK_LOGGED: {
    code: 'LINK_LOGGED',
    category: 'Taint & Data Flow',
    plainDescription: 'Data link between input source and tool argument was recorded for provenance.',
    typicalAction: 'ALLOW',
  },
  LINK_SCAN_LIMIT: {
    code: 'LINK_SCAN_LIMIT',
    category: 'Taint & Data Flow',
    plainDescription: 'Provenance tracking link search hit maximum depth or scan count limits.',
    typicalAction: 'ASK',
  },
  MISSING_ARGUMENT: {
    code: 'MISSING_ARGUMENT',
    category: 'Argument Validation',
    plainDescription: 'A required argument defined in the tool schema was omitted by the agent.',
    typicalAction: 'BLOCK',
  },
  NO_APPROVER: {
    code: 'NO_APPROVER',
    category: 'Approval Flow',
    plainDescription: 'Human approval was required by policy but no approver callback was configured.',
    typicalAction: 'BLOCK',
  },
  OUTPUT_HELD: {
    code: 'OUTPUT_HELD',
    category: 'Output Inspection',
    plainDescription: 'Tool output contained flagged suspicious content and was withheld from the model.',
    typicalAction: 'BLOCK',
  },
  OUTPUT_MASKED: {
    code: 'OUTPUT_MASKED',
    category: 'Output Inspection',
    plainDescription: 'Tool output contained sensitive tokens or suspicious spans that were redacted.',
    typicalAction: 'ALLOW',
  },
  OUTPUT_NOT_TEXT: {
    code: 'OUTPUT_NOT_TEXT',
    category: 'Output Inspection',
    plainDescription: 'Tool output is non-text binary data that could not be verified by text scanners.',
    typicalAction: 'ASK',
  },
  OUTPUT_OVERSIZE: {
    code: 'OUTPUT_OVERSIZE',
    category: 'Output Inspection',
    plainDescription: 'Tool output exceeded the configured size limit for safe in-memory scanning.',
    typicalAction: 'BLOCK',
  },
  OUTPUT_PASSED: {
    code: 'OUTPUT_PASSED',
    category: 'Output Inspection',
    plainDescription: 'Tool output was scanned and verified free of injection indicators.',
    typicalAction: 'ALLOW',
  },
  OUTPUT_SCAN_DISABLED: {
    code: 'OUTPUT_SCAN_DISABLED',
    category: 'Output Inspection',
    plainDescription: 'Output scanning is disabled by configuration for this tool.',
    typicalAction: 'ALLOW',
  },
  OUTPUT_SCAN_FAILED: {
    code: 'OUTPUT_SCAN_FAILED',
    category: 'Output Inspection',
    plainDescription: 'Scanning of tool output encountered an error or unparseable content.',
    typicalAction: 'BLOCK',
  },
  OUTPUT_UNREVIEWED: {
    code: 'OUTPUT_UNREVIEWED',
    category: 'Output Inspection',
    plainDescription: 'Tool output has not yet undergone required security inspection.',
    typicalAction: 'ASK',
  },
  PATH_NOT_ALLOWED: {
    code: 'PATH_NOT_ALLOWED',
    category: 'Policy & Constraints',
    plainDescription: 'The requested file or directory path is outside permitted policy roots.',
    typicalAction: 'BLOCK',
  },
  POLICY_INVALID: {
    code: 'POLICY_INVALID',
    category: 'System & Session State',
    plainDescription: 'The loaded security policy failed validation or schema verification.',
    typicalAction: 'BLOCK',
  },
  RECIPIENT_NOT_ALLOWED: {
    code: 'RECIPIENT_NOT_ALLOWED',
    category: 'Policy & Constraints',
    plainDescription: 'The target email or message recipient is outside permitted destinations.',
    typicalAction: 'BLOCK',
  },
  RETRY_LIMIT_REACHED: {
    code: 'RETRY_LIMIT_REACHED',
    category: 'System & Session State',
    plainDescription: 'The agent exceeded maximum allowed retry attempts after blocked actions.',
    typicalAction: 'BLOCK',
  },
  RULES_NOT_IMPLEMENTED: {
    code: 'RULES_NOT_IMPLEMENTED',
    category: 'System & Session State',
    plainDescription: 'Required rule validation logic is not implemented for the target tool.',
    typicalAction: 'BLOCK',
  },
  SESSION_HALTED: {
    code: 'SESSION_HALTED',
    category: 'System & Session State',
    plainDescription: 'The session has been halted due to repeated policy breaches or loop guard tripping.',
    typicalAction: 'BLOCK',
  },
  SESSION_TAINTED_HIGH_RISK: {
    code: 'SESSION_TAINTED_HIGH_RISK',
    category: 'Taint & Data Flow',
    plainDescription: 'Session context contains high-severity injection indicators from prior steps.',
    typicalAction: 'BLOCK',
  },
  TASK_FIT_DOUBTFUL: {
    code: 'TASK_FIT_DOUBTFUL',
    category: 'System & Session State',
    plainDescription: 'The requested action does not align with the stated high-level task goal.',
    typicalAction: 'ASK',
  },
  TOOL_NOT_ALLOWED_FOR_TASK: {
    code: 'TOOL_NOT_ALLOWED_FOR_TASK',
    category: 'Policy & Constraints',
    plainDescription: 'The tool is not permitted for use within the current task scope.',
    typicalAction: 'BLOCK',
  },
  TOOL_OUTPUT_HELD: {
    code: 'TOOL_OUTPUT_HELD',
    category: 'Output Inspection',
    plainDescription: 'Tool output was held pending reviewer authorization before disclosure.',
    typicalAction: 'ASK',
  },
  UNEXPECTED_ARGUMENT: {
    code: 'UNEXPECTED_ARGUMENT',
    category: 'Argument Validation',
    plainDescription: 'An unrecognized argument parameter was supplied to the tool.',
    typicalAction: 'BLOCK',
  },
  UNKNOWN_TOOL: {
    code: 'UNKNOWN_TOOL',
    category: 'Argument Validation',
    plainDescription: 'The requested tool is not defined in the policy or registry.',
    typicalAction: 'BLOCK',
  },
  URL_NOT_ALLOWED: {
    code: 'URL_NOT_ALLOWED',
    category: 'Policy & Constraints',
    plainDescription: 'The target URL violates policy constraints or domain restrictions.',
    typicalAction: 'BLOCK',
  },
  USER_APPROVED: {
    code: 'USER_APPROVED',
    category: 'Approval Flow',
    plainDescription: 'A human reviewer evaluated the held request and explicitly approved it.',
    typicalAction: 'ALLOW',
  },
  USER_DENIED: {
    code: 'USER_DENIED',
    category: 'Approval Flow',
    plainDescription: 'A human reviewer evaluated the held request and explicitly denied it.',
    typicalAction: 'BLOCK',
  },
  USER_PROVIDED_VALUE: {
    code: 'USER_PROVIDED_VALUE',
    category: 'Taint & Data Flow',
    plainDescription: 'The argument value was verified to have originated directly from trusted user input.',
    typicalAction: 'ALLOW',
  },
  WRONG_ARGUMENT_TYPE: {
    code: 'WRONG_ARGUMENT_TYPE',
    category: 'Argument Validation',
    plainDescription: 'An argument value does not match the required schema data type.',
    typicalAction: 'BLOCK',
  },
};

export function getReasonCodeMeta(code: string): ReasonCodeMeta {
  if (code in REASON_CODE_METADATA) {
    return REASON_CODE_METADATA[code];
  }
  return {
    code,
    category: 'Uncategorized',
    plainDescription: 'Custom or unknown reason code.',
    typicalAction: 'MIXED',
  };
}
