// EU AI Act Compliance Mapping for Agent Passport System
// Maps protocol artifacts to EU AI Act requirements (enforcement: August 2, 2026)
// Articles 9-15 (high-risk), Article 50 (transparency)

import { createDID } from './did.js'
import type { AgentPassport } from '../types/passport.js'
import type {
  RiskCategory, EUAIActArticle, ComplianceProfile,
  TransparencyDisclosure, EUComplianceReport, EUComplianceGap
} from '../types/euaiact.js'

// High-risk use case keywords from Annex III
const HIGH_RISK_KEYWORDS = [
  'biometric', 'critical_infrastructure', 'education', 'employment',
  'credit', 'law_enforcement', 'migration', 'justice', 'democratic',
  'recruitment', 'hiring', 'scoring', 'medical', 'safety'
]

/**
 * Classify an agent's risk category based on its capabilities and use context.
 */
export function classifyRisk(
  capabilities: string[],
  useContext?: string
): RiskCategory {
  const combined = [...capabilities, useContext || ''].join(' ').toLowerCase()
  if (HIGH_RISK_KEYWORDS.some(kw => combined.includes(kw))) return 'high'
  // Agents that interact with humans are at least "limited" risk (Article 50)
  if (capabilities.some(c => /chat|convers|interact|customer|support/i.test(c))) return 'limited'
  return 'minimal'
}


/**
 * Map AEOESS protocol features to EU AI Act articles.
 * Returns the compliance status for each relevant article.
 */
export function mapArticles(riskCategory: RiskCategory): EUAIActArticle[] {
  const articles: EUAIActArticle[] = []

  // Article 50 applies to ALL AI systems that interact with humans
  articles.push({
    article: 50,
    title: 'Transparency Obligations',
    description: 'AI systems must disclose to users that they are interacting with AI',
    aeoessMapping: 'Agent Passport identity + generateTransparencyDisclosure()',
    complianceStatus: 'full'
  })

  if (riskCategory === 'high' || riskCategory === 'limited') {
    articles.push({
      article: 13,
      title: 'Transparency and Provision of Information',
      description: 'High-risk systems must be designed to allow deployers to interpret output',
      aeoessMapping: 'Intent declaration + policy evaluation chain provides full action transparency',
      complianceStatus: 'full'
    })
  }

  if (riskCategory === 'high') {
    articles.push(
      {
        article: 9,
        title: 'Risk Management System',
        description: 'Continuous risk identification and mitigation throughout lifecycle',
        aeoessMapping: 'Values Floor policy engine with graduated enforcement (inline/audit/warn)',
        complianceStatus: 'full'
      },
      {
        article: 10,
        title: 'Data and Data Governance',
        description: 'Training data must be relevant, representative, and governed',
        aeoessMapping: 'Merkle attribution tracks data provenance; manual documentation needed for training data',
        complianceStatus: 'partial'
      },
      {
        article: 11,
        title: 'Technical Documentation',
        description: 'Detailed documentation of system design, development, and capabilities',
        aeoessMapping: 'Passport metadata + capability declarations + floor attestations; additional docs manual',
        complianceStatus: 'partial'
      },
      {
        article: 12,
        title: 'Record-Keeping',
        description: 'Automatic logging of events throughout high-risk system lifetime',
        aeoessMapping: '3-signature policy chain (intent + evaluation + receipt) provides tamper-proof audit log',
        complianceStatus: 'full'
      },
      {
        article: 14,
        title: 'Human Oversight',
        description: 'High-risk systems must allow effective human oversight',
        aeoessMapping: 'Human approval gates (commerce), cascade revocation, delegation scope limits',
        complianceStatus: 'full'
      },
      {
        article: 15,
        title: 'Accuracy, Robustness and Cybersecurity',
        description: 'Systems must achieve appropriate levels of accuracy and security',
        aeoessMapping: 'Ed25519 cryptographic identity, 23 adversarial test scenarios, cascade revocation',
        complianceStatus: 'partial'
      }
    )
  }

  return articles
}

/**
 * Generate Article 50 transparency disclosure for an agent.
 */
export function generateTransparencyDisclosure(
  passport: AgentPassport,
  operatorName: string,
  options?: { limitations?: string[]; contactInfo?: string }
): TransparencyDisclosure {
  return {
    isAIAgent: true,
    agentName: passport.agentName,
    operatorName,
    capabilities: passport.capabilities,
    limitations: options?.limitations || [
      'This agent operates within scoped delegation boundaries',
      'Actions are subject to Values Floor policy evaluation',
      'Human oversight can revoke authority at any time'
    ],
    humanOversightMechanism: 'Delegation cascade revocation + human approval gates for high-value actions',
    contactInfo: options?.contactInfo
  }
}


/**
 * Generate a full compliance profile for an agent.
 */
export function generateComplianceProfile(
  passport: AgentPassport,
  operatorName: string,
  options?: {
    useContext?: string
    limitations?: string[]
    contactInfo?: string
    floorAttested?: boolean
    floorVersion?: string
  }
): ComplianceProfile {
  const riskCategory = classifyRisk(passport.capabilities, options?.useContext)
  const articles = mapArticles(riskCategory)
  const disclosure = generateTransparencyDisclosure(passport, operatorName, options)

  const fullCount = articles.filter(a => a.complianceStatus === 'full').length
  const score = articles.length > 0 ? Math.round((fullCount / articles.length) * 100) : 100

  return {
    agentId: passport.agentId,
    did: createDID(passport.publicKey),
    riskCategory,
    assessmentDate: new Date().toISOString(),
    articles,
    floorVersion: options?.floorVersion || '0.1',
    floorAttested: options?.floorAttested ?? false,
    transparencyDisclosure: disclosure,
    score
  }
}

/**
 * Identify compliance gaps and generate remediation recommendations.
 */
export function identifyGaps(profile: ComplianceProfile): EUComplianceGap[] {
  const gaps: EUComplianceGap[] = []

  for (const article of profile.articles) {
    if (article.complianceStatus === 'partial') {
      if (article.article === 10) {
        gaps.push({
          article: 10,
          requirement: 'Training data governance and provenance documentation',
          currentState: 'Merkle attribution tracks runtime data provenance but training data documentation is manual',
          remediation: 'Add training data manifest to passport metadata with dataset hashes and governance records',
          priority: 'high'
        })
      }
      if (article.article === 11) {
        gaps.push({
          article: 11,
          requirement: 'Complete technical documentation per Annex IV',
          currentState: 'Passport metadata and floor attestations provide partial documentation',
          remediation: 'Generate Annex IV compliant documentation from passport, delegation, and policy chain data',
          priority: 'high'
        })
      }
      if (article.article === 15) {
        gaps.push({
          article: 15,
          requirement: 'Documented accuracy metrics and robustness testing',
          currentState: '23 adversarial scenarios tested; accuracy metrics are domain-specific',
          remediation: 'Add benchmark results and accuracy metrics to passport metadata',
          priority: 'medium'
        })
      }
    }
  }

  if (!profile.floorAttested) {
    gaps.push({
      article: 9,
      requirement: 'Active risk management attestation',
      currentState: 'Agent has not attested to Values Floor',
      remediation: 'Call attestToFloor() to formally attest to the Values Floor principles',
      priority: 'critical'
    })
  }

  return gaps
}

/**
 * Generate a full compliance report with recommendations.
 */
export function generateComplianceReport(
  passport: AgentPassport,
  operatorName: string,
  options?: {
    useContext?: string
    limitations?: string[]
    contactInfo?: string
    floorAttested?: boolean
    floorVersion?: string
  }
): EUComplianceReport {
  const profile = generateComplianceProfile(passport, operatorName, options)
  const gaps = identifyGaps(profile)

  const recommendations: string[] = []

  if (profile.riskCategory === 'high') {
    recommendations.push('Register this system in the EU AI database before deployment')
    recommendations.push('Complete conformity assessment per Article 43')
    recommendations.push('Implement post-market monitoring per Article 72')
  }

  if (gaps.some(g => g.priority === 'critical')) {
    recommendations.push('URGENT: Address critical compliance gaps before August 2, 2026 enforcement date')
  }

  if (!profile.floorAttested) {
    recommendations.push('Attest to Values Floor to demonstrate risk management commitment')
  }

  recommendations.push('Maintain policy chain records (intent + evaluation + receipt) for minimum 10 years per Article 12')
  recommendations.push('Ensure transparency disclosure is presented before first user interaction per Article 50')

  return {
    profile,
    generatedAt: new Date().toISOString(),
    recommendations,
    gaps
  }
}
