// EU AI Act Compliance Types
// Maps Agent Passport System artifacts to EU AI Act requirements

export type RiskCategory = 'unacceptable' | 'high' | 'limited' | 'minimal'

export interface EUAIActArticle {
  article: number
  title: string
  description: string
  aeoessMapping: string
  complianceStatus: 'full' | 'partial' | 'manual_required'
}

export interface ComplianceProfile {
  agentId: string
  did: string
  riskCategory: RiskCategory
  assessmentDate: string
  articles: EUAIActArticle[]
  floorVersion: string
  floorAttested: boolean
  transparencyDisclosure: TransparencyDisclosure
  score: number // 0-100
}

export interface TransparencyDisclosure {
  isAIAgent: true
  agentName: string
  operatorName: string
  capabilities: string[]
  limitations: string[]
  humanOversightMechanism: string
  contactInfo?: string
}

export interface EUComplianceReport {
  profile: ComplianceProfile
  generatedAt: string
  recommendations: string[]
  gaps: EUComplianceGap[]
  signature?: string
}

export interface EUComplianceGap {
  article: number
  requirement: string
  currentState: string
  remediation: string
  priority: 'critical' | 'high' | 'medium' | 'low'
}
