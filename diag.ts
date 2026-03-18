import { generateKeyPair, createPassport, signPassport, loadFloor, attestFloor, createDelegation, ProxyGateway, canonicalize, sign } from './src/index.js'
import { readFileSync } from 'fs'

const floorYaml = readFileSync('values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)
const gwKeys = generateKeyPair()
const agentKeys = generateKeyPair()
const principalKeys = generateKeyPair()

const passport = signPassport(createPassport({
  agentId: 'test-agent', capabilities: ['data:read'],
  publicKey: agentKeys.publicKey
}), agentKeys.privateKey)

const attestation = attestFloor('test-agent', agentKeys.publicKey, floor.version, [], agentKeys.privateKey)

const delegation = createDelegation({
  delegatedTo: agentKeys.publicKey, delegatedBy: principalKeys.publicKey,
  privateKey: principalKeys.privateKey,
  scope: ['data:read'], spendLimit: 5000, expiresInHours: 24
})

const gw = new ProxyGateway({
  gatewayId: 'gw-test', gatewayPublicKey: gwKeys.publicKey,
  gatewayPrivateKey: gwKeys.privateKey, floor,
  enableReputationGating: true,
}, async () => ({ success: true, result: 'ok' }))

const regResult = gw.registerAgent(passport, attestation, [delegation])
console.log('registerAgent:', JSON.stringify(regResult))
console.log('tier:', JSON.stringify(gw.getAgentTier('test-agent')))
console.log('rep mu/sigma:', gw.getAgentReputation('test-agent')?.mu, gw.getAgentReputation('test-agent')?.sigma)

// Test processToolCall
async function run() {
  const payload = canonicalize({ requestId: 'r1', agentId: 'test-agent', tool: 'read', params: {} })
  const result = await gw.processToolCall({
    requestId: 'r1', agentId: 'test-agent', agentPublicKey: agentKeys.publicKey,
    signature: sign(payload, agentKeys.privateKey),
    tool: 'read', params: {}, scopeRequired: 'data:read',
    delegationId: delegation.delegationId
  })
  console.log('toolCall:', JSON.stringify({ executed: result.executed, denialReason: result.denialReason }))
}
run().catch(e => console.error(e))
