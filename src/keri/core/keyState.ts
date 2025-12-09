import { components } from '../../types/keria-api-schema.ts';

export type KeyState = components['schemas']['KeyStateRecord'];

export type EstablishmentState = components['schemas']['StateEERecord'];

/**
 * Marker interface for state configuring an IdentifierManager.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface IdentifierManagerState {}

/**
 * Defining configuration parameters for a specified, deterministic salt of an IdentifierManager.
 */
export type SaltyKeyState = components['schemas']['SaltyState'];

/**
 * Defining configuration parameters for a random seed identifier manager.
 */
export type RandyKeyState = components['schemas']['RandyKeyState'];

/**
 * Defining properties a multi-signature group identifier manager.
 */
export type GroupKeyState = components['schemas']['GroupKeyState'];

/**
 * Defining properties for an external module identifier manager that uses externally managed keys such as in an HSM or a KMS system.
 */
export type ExternState = components['schemas']['ExternState'];

/**
 * Defining properties of an identifier habitat, know as a Hab in KERIpy.
 */
export type HabState = components['schemas']['HabState'];

export type Icp =
    | components['schemas']['ICP_V_1']
    | components['schemas']['ICP_V_2'];
export type Ixn =
    | components['schemas']['IXN_V_1']
    | components['schemas']['IXN_V_2'];
export type ExnV1 = components['schemas']['EXN_V_1'];
export type Dip =
    | components['schemas']['DIP_V_1']
    | components['schemas']['DIP_V_2'];
export type Rot =
    | components['schemas']['ROT_V_1']
    | components['schemas']['ROT_V_2'];
export type ExnEmbeds = components['schemas']['ExnEmbeds'];
export type MultisigRpyEmbeds = components['schemas']['MultisigRpyEmbeds'];

/**
 * Defining Operation types
 */
export type OOBIOperation = components['schemas']['OOBIOperation'];
export type QueryOperation = components['schemas']['QueryOperation'];
export type EndRoleOperation = components['schemas']['EndRoleOperation'];
export type WitnessOperation = components['schemas']['WitnessOperation'];
export type DelegationOperation = components['schemas']['DelegationOperation'];
export type RegistryOperation = components['schemas']['RegistryOperation'];
export type LocSchemeOperation = components['schemas']['LocSchemeOperation'];
export type ChallengeOperation = components['schemas']['ChallengeOperation'];
export type ExchangeOperation = components['schemas']['ExchangeOperation'];
export type SubmitOperation = components['schemas']['SubmitOperation'];
export type DoneOperation = components['schemas']['DoneOperation'];
export type CredentialOperation = components['schemas']['CredentialOperation'];
export type GroupOperation = components['schemas']['GroupOperation'];
export type DelegatorOperation = components['schemas']['DelegatorOperation'];
export type GenericOperation =
    | OOBIOperation
    | QueryOperation
    | EndRoleOperation
    | WitnessOperation
    | DelegationOperation
    | RegistryOperation
    | LocSchemeOperation
    | ChallengeOperation
    | ExchangeOperation
    | SubmitOperation
    | DoneOperation
    | CredentialOperation
    | GroupOperation
    | DelegatorOperation;
