// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Shared CSV→list helper used by every binding rail's V2Delegation
// crosswalk. Splits on comma, trims, drops empty.
export function csvToList(s: string | undefined): string[] {
  if (!s) return []
  return s.split(',').map((x) => x.trim()).filter(Boolean)
}
