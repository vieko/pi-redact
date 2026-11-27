import { findVendorKeys } from "./detect.ts";

/** Families for values without a vendor shape: `password-key` by its key, the rest by shape. */
export const FAMILIES = ["password-key", "jwt", "uuid", "prefixed-id", "identifier", "high-entropy"] as const;

// Vendor rules take precedence so audit counts retain their public shape label.
// `byKey` says the detector took the value for the name in front of it
// (`password=`, `"secret":`), so its shape says nothing about why it is hidden.
export function familyOf(value: string, byKey = false): string {
	const vendor = findVendorKeys(value)[0];
	if (vendor) return vendor.family;
	if (byKey) return "password-key";
	// A JWT, or one cut after its payload. Header and payload are base64 JSON.
	if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/.test(value)) return "jwt";
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return "uuid";
	if (/^[a-z][a-z0-9]{1,15}_[A-Za-z0-9]{8,}$/.test(value)) return "prefixed-id";
	if (/^(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9]+$/.test(value)) return "identifier";
	return "high-entropy";
}
