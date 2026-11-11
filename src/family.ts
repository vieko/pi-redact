import { findVendorKeys } from "./detect.ts";

/** Shape classes for values without a vendor-specific family. */
export const FAMILIES = ["uuid", "prefixed-id", "identifier", "high-entropy"] as const;

// Vendor rules take precedence so audit counts retain their public shape label.
export function familyOf(value: string): string {
	const vendor = findVendorKeys(value)[0];
	if (vendor) return vendor.family;
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return "uuid";
	if (/^[a-z][a-z0-9]{1,15}_[A-Za-z0-9]{8,}$/.test(value)) return "prefixed-id";
	if (/^(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9]+$/.test(value)) return "identifier";
	return "high-entropy";
}
