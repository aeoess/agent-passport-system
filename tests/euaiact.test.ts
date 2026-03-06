// Tests for EU AI Act Compliance Mapping
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  classifyRisk, mapArticles, generateTransparencyDisclosure,
  generateComplianceProfile, identifyGaps, generateComplianceReport
} from '../src/index.js'

describe('EU AI Act Compliance', () => {

  describe('Risk Classification', () => {
    it('classifies biometric use as high risk', () => {
      assert.equal(classifyRisk(['biometric_identification', 'facial_recognition']), 'high')
    })

    it('classifies employment screening as high risk', () => {
      assert.equal(classifyRisk(['resume_screening'], 'recruitment and hiring'), 'high')
    })

    it('classifies chatbot as limited risk', () => {
      assert.equal(classifyRisk(['customer_support', 'chat_interaction']), 'limited')
    })

    it('classifies data analysis as minimal risk', () => {
      assert.equal(classifyRisk(['data_analysis', 'report_generation']), 'minimal')
    })

    it('classifies credit scoring as high risk', () => {
      assert.equal(classifyRisk(['credit_assessment', 'risk_scoring']), 'high')
    })
  })

  describe('Article Mapping', () => {
    it('maps Article 50 for all risk categories', () => {
      const minimal = mapArticles('minimal')
      assert.ok(minimal.some(a => a.article === 50))
    })

    it('maps full article set for high-risk systems', () => {
      const high = mapArticles('high')
      const articleNumbers = high.map(a => a.article)
      assert.ok(articleNumbers.includes(9), 'Missing Article 9 Risk Management')
      assert.ok(articleNumbers.includes(12), 'Missing Article 12 Record-Keeping')
      assert.ok(articleNumbers.includes(14), 'Missing Article 14 Human Oversight')
      assert.ok(articleNumbers.includes(50), 'Missing Article 50 Transparency')
    })

    it('marks record-keeping as fully compliant via policy chain', () => {
      const high = mapArticles('high')
      const art12 = high.find(a => a.article === 12)
      assert.equal(art12?.complianceStatus, 'full')
      assert.ok(art12?.aeoessMapping.includes('3-signature'))
    })
  })

  describe('Transparency Disclosure', () => {
    it('generates Article 50 compliant disclosure', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-1', agentName: 'SupportBot', ownerAlias: 'operator',
        mission: 'Customer support agent', capabilities: ['chat_interaction', 'faq_lookup'],
        runtime: { platform: 'claude', models: ['claude-4'], toolsCount: 5, memoryType: 'persistent' }
      })
      const disclosure = generateTransparencyDisclosure(signedPassport.passport, 'Acme Corp', {
        contactInfo: 'compliance@acme.com'
      })
      assert.equal(disclosure.isAIAgent, true)
      assert.equal(disclosure.agentName, 'SupportBot')
      assert.equal(disclosure.operatorName, 'Acme Corp')
      assert.equal(disclosure.contactInfo, 'compliance@acme.com')
      assert.ok(disclosure.limitations.length > 0)
      assert.ok(disclosure.humanOversightMechanism.includes('revocation'))
    })
  })

  describe('Compliance Profile', () => {
    it('generates full profile for high-risk agent', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-2', agentName: 'HRScreener', ownerAlias: 'hr-dept',
        mission: 'Resume screening and candidate assessment',
        capabilities: ['resume_screening', 'employment_matching', 'hiring_recommendation'],
        runtime: { platform: 'custom', models: ['gpt-4'], toolsCount: 10, memoryType: 'ephemeral' }
      })
      const profile = generateComplianceProfile(signedPassport.passport, 'BigCorp HR', {
        floorAttested: true, floorVersion: '0.1'
      })
      assert.equal(profile.riskCategory, 'high')
      assert.ok(profile.articles.length >= 6)
      assert.ok(profile.did.startsWith('did:aps:'))
      assert.ok(profile.score > 0)
    })

    it('scores minimal-risk agents higher', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-3', agentName: 'DataCruncher', ownerAlias: 'analytics',
        mission: 'Internal data analysis', capabilities: ['data_analysis', 'report_generation'],
        runtime: { platform: 'node', models: ['local'], toolsCount: 3, memoryType: 'none' }
      })
      const profile = generateComplianceProfile(signedPassport.passport, 'AnalyticsCo')
      assert.equal(profile.riskCategory, 'minimal')
      assert.equal(profile.score, 100) // only Article 50, fully compliant
    })
  })

  describe('Gap Analysis', () => {
    it('identifies critical gap when floor not attested', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-4', agentName: 'MedBot', ownerAlias: 'hospital',
        mission: 'Medical record analysis', capabilities: ['medical_analysis', 'patient_data'],
        runtime: { platform: 'custom', models: ['med-llm'], toolsCount: 8, memoryType: 'encrypted' }
      })
      const profile = generateComplianceProfile(signedPassport.passport, 'Hospital Inc', {
        floorAttested: false
      })
      const gaps = identifyGaps(profile)
      assert.ok(gaps.some(g => g.priority === 'critical'))
      assert.ok(gaps.some(g => g.article === 9 && g.requirement.includes('attestation')))
    })

    it('identifies training data governance gap for high-risk', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-5', agentName: 'CreditBot', ownerAlias: 'bank',
        mission: 'Credit scoring', capabilities: ['credit_assessment'],
        runtime: { platform: 'custom', models: ['fin-model'], toolsCount: 5, memoryType: 'persistent' }
      })
      const profile = generateComplianceProfile(signedPassport.passport, 'Bank Corp', {
        floorAttested: true
      })
      const gaps = identifyGaps(profile)
      assert.ok(gaps.some(g => g.article === 10))
    })
  })

  describe('Full Compliance Report', () => {
    it('generates complete report with recommendations', () => {
      const { signedPassport } = createPassport({
        agentId: 'eu-test-6', agentName: 'JudgeAssist', ownerAlias: 'court',
        mission: 'Legal case analysis', capabilities: ['justice_analysis', 'case_research'],
        runtime: { platform: 'custom', models: ['legal-llm'], toolsCount: 12, memoryType: 'persistent' }
      })
      const report = generateComplianceReport(signedPassport.passport, 'Court System', {
        useContext: 'administration of justice', floorAttested: false
      })
      assert.equal(report.profile.riskCategory, 'high')
      assert.ok(report.recommendations.length > 0)
      assert.ok(report.gaps.length > 0)
      assert.ok(report.recommendations.some(r => r.includes('EU AI database')))
      assert.ok(report.recommendations.some(r => r.includes('August 2, 2026')))
    })
  })
})
