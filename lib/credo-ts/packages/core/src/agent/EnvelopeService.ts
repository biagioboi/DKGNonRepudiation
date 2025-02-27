import type { AgentMessage } from './AgentMessage'
import type { AgentContext } from './context'
import type { EncryptedMessage, PlaintextMessage } from '../types'

import { InjectionSymbols } from '../constants'
import { Key, KeyType } from '../crypto'
import { Logger } from '../logger'
import { ForwardMessage } from '../modules/routing/messages'
import { inject, injectable } from '../plugins'

export interface EnvelopeKeys {
  recipientKeys: Key[]
  routingKeys: Key[]
  senderKey: Key | null
}

@injectable()
export class EnvelopeService {
  private logger: Logger

  public constructor(@inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
  }

  public async packMessage(
    agentContext: AgentContext,
    payload: AgentMessage,
    keys: EnvelopeKeys
  ): Promise<EncryptedMessage> {
    const { recipientKeys, routingKeys, senderKey } = keys
    let recipientKeysBase58 = recipientKeys.map((key) => key.publicKeyBase58)
    const routingKeysBase58 = routingKeys.map((key) => key.publicKeyBase58)
    const senderKeyBase58 = senderKey && senderKey.publicKeyBase58

    // pass whether we want to use legacy did sov prefix
    const message = payload.toJSON({ useDidSovPrefixWhereAllowed: agentContext.config.useDidSovPrefixWhereAllowed })

    this.logger.debug(`Pack outbound message ${message['@type']}`)

    let encryptedMessage = await agentContext.wallet.pack(message, recipientKeysBase58, senderKeyBase58 ?? undefined)

    // If the message has routing keys (mediator) pack for each mediator
    for (const routingKeyBase58 of routingKeysBase58) {
      const forwardMessage = new ForwardMessage({
        // Forward to first recipient key
        to: recipientKeysBase58[0],
        message: encryptedMessage,
      })
      recipientKeysBase58 = [routingKeyBase58]
      this.logger.debug('Forward message created', forwardMessage)

      const forwardJson = forwardMessage.toJSON({
        useDidSovPrefixWhereAllowed: agentContext.config.useDidSovPrefixWhereAllowed,
      })

      // Forward messages are anon packed
      encryptedMessage = await agentContext.wallet.pack(forwardJson, [routingKeyBase58], undefined)
    }

    return encryptedMessage
  }

  public async packMessageWithReturn(
    agentContext: AgentContext,
    payload: AgentMessage,
    keys: EnvelopeKeys
  ): Promise<any> {
    const { recipientKeys, routingKeys, senderKey } = keys
    let recipientKeysBase58 = recipientKeys.map((key) => key.publicKeyBase58)
    const routingKeysBase58 = routingKeys.map((key) => key.publicKeyBase58)
    if (routingKeysBase58.length > 0) {
      new Error("Routing keys not supported in this case")
    }
    const senderKeyBase58 = senderKey && senderKey.publicKeyBase58

    // pass whether we want to use legacy did sov prefix
    const message = payload.toJSON({ useDidSovPrefixWhereAllowed: agentContext.config.useDidSovPrefixWhereAllowed })

    this.logger.debug(`Pack outbound message ${message['@type']}`)

    return await agentContext.wallet.packWithReturn(message, recipientKeysBase58, senderKeyBase58 ?? undefined)

  }

  public async unpackMessage(
    agentContext: AgentContext,
    encryptedMessage: EncryptedMessage
  ): Promise<DecryptedMessageContext> {
    const decryptedMessage = await agentContext.wallet.unpack(encryptedMessage)
    const { recipientKey, senderKey, plaintextMessage } = decryptedMessage
    return {
      recipientKey: recipientKey ? Key.fromPublicKeyBase58(recipientKey, KeyType.Ed25519) : undefined,
      senderKey: senderKey ? Key.fromPublicKeyBase58(senderKey, KeyType.Ed25519) : undefined,
      plaintextMessage,

    }
  }

  public async unpackMessageWithReturn(
      agentContext: AgentContext,
      encryptedMessage: EncryptedMessage
  ): Promise<DecryptedMessageContext> {
    const decryptedMessage = await agentContext.wallet.unpackWithReturn(encryptedMessage)
    const { recipientKey, senderKey, plaintextMessage, payloadKey } = decryptedMessage
    return {
      recipientKey: recipientKey ? Key.fromPublicKeyBase58(recipientKey, KeyType.Ed25519) : undefined,
      senderKey: senderKey ? Key.fromPublicKeyBase58(senderKey, KeyType.Ed25519) : undefined,
      plaintextMessage,
      payloadKey
    }
  }
}

export interface DecryptedMessageContext {
  plaintextMessage: PlaintextMessage
  senderKey?: Key
  recipientKey?: Key,
  payloadKey?:any
}


