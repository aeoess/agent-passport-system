/**
 * APS v2 Policy Profiles (Section 9.14)
 *
 * Jurisdiction-tagged, domain-tagged compliance modules. The core protocol
 * governs identity, delegation, provenance. Policy Profiles govern child
 * safety, fraud prevention, IP, speech, finance, healthcare — everything
 * politically contingent or sector-specific.
 */

export interface ProfileConstraint {
  type: 'required_review' | 'prohibited_action' | 'extra_provenance' |
        'mandatory_human_signoff' | 'retention_rule' | 'complaint_route' |
        'audience_handling' | 'content_restriction'
  description: string
  parameters: Record<string, string | number | boolean>
}

export interface PolicyProfile {
  id: string; name: string;
  jurisdiction: string; domain: string; version: string;
  constraints: ProfileConstraint[];
  created_at: string;
}

export interface ProfileAttachment {
  id: string; profile_id: string;
  target_type: 'agent' | 'workflow' | 'deployment';
  target_id: string;
  attached_at: string; attached_by: string;
}

const profiles: Map<string, PolicyProfile> = new Map()
const attachments: ProfileAttachment[] = []

export function createProfile(params: {
  name: string; jurisdiction: string; domain: string;
  version: string; constraints: ProfileConstraint[];
}): PolicyProfile {
  const p: PolicyProfile = {
    id: `profile-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: params.name, jurisdiction: params.jurisdiction,
    domain: params.domain, version: params.version,
    constraints: params.constraints,
    created_at: new Date().toISOString(),
  }
  profiles.set(p.id, p)
  return p
}

export function attachProfile(profileId: string, targetType: ProfileAttachment['target_type'],
  targetId: string, attachedBy: string): ProfileAttachment {
  if (!profiles.has(profileId)) throw new Error(`Profile ${profileId} not found`)
  const a: ProfileAttachment = {
    id: `attach-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    profile_id: profileId, target_type: targetType,
    target_id: targetId, attached_at: new Date().toISOString(),
    attached_by: attachedBy,
  }
  attachments.push(a)
  return a
}

export function getProfilesForTarget(targetType: string, targetId: string): PolicyProfile[] {
  const attached = attachments.filter(a => a.target_type === targetType && a.target_id === targetId)
  return attached.map(a => profiles.get(a.profile_id)).filter(Boolean) as PolicyProfile[]
}

export function checkProfileCompliance(
  targetType: string, targetId: string,
  actionMetadata: Record<string, string>
): { compliant: boolean; violations: string[] } {
  const targetProfiles = getProfilesForTarget(targetType, targetId)
  const violations: string[] = []

  for (const profile of targetProfiles) {
    for (const c of profile.constraints) {
      if (c.type === 'prohibited_action') {
        const actionType = actionMetadata['action_type'] || ''
        const prohibited = String(c.parameters['action'] || '')
        if (actionType === prohibited) {
          violations.push(`[${profile.name}] Prohibited action: ${prohibited}`)
        }
      }
      if (c.type === 'mandatory_human_signoff') {
        const hasSignoff = actionMetadata['human_signoff'] === 'true'
        if (!hasSignoff) {
          violations.push(`[${profile.name}] Requires human signoff: ${c.description}`)
        }
      }
      if (c.type === 'content_restriction') {
        const content = actionMetadata['content'] || ''
        const restricted = String(c.parameters['keyword'] || '')
        if (restricted && content.toLowerCase().includes(restricted.toLowerCase())) {
          violations.push(`[${profile.name}] Content restriction: ${c.description}`)
        }
      }
    }
  }
  return { compliant: violations.length === 0, violations }
}

export function detachProfile(attachmentId: string): void {
  const idx = attachments.findIndex(a => a.id === attachmentId)
  if (idx >= 0) attachments.splice(idx, 1)
}

export function listActiveProfiles(): PolicyProfile[] { return [...profiles.values()] }
export function getProfile(id: string): PolicyProfile | undefined { return profiles.get(id) }
export function clearPolicyProfileStores(): void { profiles.clear(); attachments.length = 0 }
