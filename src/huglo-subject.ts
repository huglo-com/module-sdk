import { authError } from "./errors.js";

/** Parsed Huglo subject identifier (`huglo:<ns>:<id>`). */
export interface HugloSubject {
  readonly namespace: string;
  readonly id: string;
  /** Canonical full subject string (`huglo:<ns>:<id>`). */
  readonly subject: string;
}

const HUGLO_PREFIX = "huglo:";
const NAMESPACE_PATTERN = /^[a-z0-9]{4,16}$/;
/** Opaque id: non-empty, no colons or whitespace (Directory-issued opaque token). */
const ID_PATTERN = /^[^\s:]{1,256}$/;

/**
 * Parse and validate a Huglo subject identifier.
 * Accepts only `huglo:<ns>:<id>` with no extra segments.
 */
export function parseHugloSubject(value: string): HugloSubject {
  if (!value.startsWith(HUGLO_PREFIX)) {
    throw authError("invalid_subject", "Invalid Huglo subject identifier");
  }
  const body = value.slice(HUGLO_PREFIX.length);
  const colon = body.indexOf(":");
  if (colon < 0) {
    throw authError("invalid_subject", "Invalid Huglo subject identifier");
  }
  const namespace = body.slice(0, colon);
  const id = body.slice(colon + 1);
  if (body.indexOf(":", colon + 1) >= 0) {
    throw authError("invalid_subject", "Invalid Huglo subject identifier");
  }
  if (!NAMESPACE_PATTERN.test(namespace)) {
    throw authError("invalid_subject", "Invalid Huglo subject identifier");
  }
  if (!ID_PATTERN.test(id)) {
    throw authError("invalid_subject", "Invalid Huglo subject identifier");
  }
  return { namespace, id, subject: value };
}
