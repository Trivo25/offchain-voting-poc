import {
  Experimental,
  Circuit,
  MerkleMap,
  MerkleMapWitness,
  Poseidon,
  Field,
  Bool,
} from 'snarkyjs';

import { StateTransition, Vote, MerkleMapExtended } from './sequencer.js';
import { Nullifier } from './lib.js';
export { Prover };

function Prover(
  nullifierTree: MerkleMap,
  voterData: ReturnType<typeof MerkleMapExtended>
) {
  return Experimental.ZkProgram({
    publicInput: StateTransition,

    methods: {
      baseCase: {
        privateInputs: [Circuit.array(Vote, 3)],

        method(publicInput: StateTransition, votes: Vote[]) {
          // because we batch votes, we have to transition our nullifier root
          // from n_v1 -> n_v2 -> n_v3, thats why we store it temporary
          let tempRoot = publicInput.nullifier.before;

          // we accumulate the results of our three votes - obviously we start with 0
          let yes = Field(0);
          let no = Field(0);
          let abstained = Field(0);

          // we go through each vote
          for (let i = 0; i < 3; i++) {
            let vote = votes[i];
            // verifying signature, obviously!
            vote.verifySignature(vote.voter).assertTrue();

            // we check if the voter is actually part of the list of eligible voters that we defined at the beginning
            checkVoterEligibility(vote, voterData, publicInput).assertTrue(
              'Voter is not an eligible voter!'
            );

            // making sure the voter actually voted for this proposal, preventing replay attacks
            publicInput.proposalId.assertEquals(
              vote.proposalId,
              'Vote proposalId does not match actual proposalId!'
            );

            // check that no nullifier has been set already - if all is good, set the nullifier!
            tempRoot = checkAndSetNullifier(vote, nullifierTree, tempRoot);

            // we do this to ensure no one is casting multiple votes
            // all votes of a voter should only sum up to 1, because we cant cast two votes
            let voteCount = vote.yes.add(vote.no).add(vote.abstained);
            voteCount.assertEquals(Field(1));

            // we aggregate the results for this single vote
            yes = yes.add(vote.yes);
            no = no.add(vote.no);
            abstained = abstained.add(vote.abstained);
          }

          // we add results that we got to the ones that we started with - sum'ing them up to the final result
          // we constraint the votes to the final result
          publicInput.result.after.yes.assertEquals(
            yes.add(publicInput.result.before.yes)
          );
          publicInput.result.after.no.assertEquals(
            no.add(publicInput.result.before.no)
          );
          publicInput.result.after.abstained.assertEquals(
            abstained.add(publicInput.result.before.abstained)
          );

          // we make sure that the final nullifier root is valid
          tempRoot.assertEquals(
            publicInput.nullifier.after,
            'Invalid state transition!'
          );
        },
      },
    },
  });
}

function checkAndSetNullifier(
  vote: Vote,
  nullifierTree: MerkleMap,
  nullifierRoot: Field
) {
  let expectedNullifier = Nullifier(vote.voter, vote.proposalId);

  let nullifierWitness = Circuit.witness(MerkleMapWitness, () => {
    return nullifierTree.getWitness(expectedNullifier);
  });

  let [root] = nullifierWitness.computeRootAndKey(Field(0));

  // we expect that a 0 is set as position [expectedNullifier] (voter key and proposal id), so if it matches it means the nullifier hasn't been set yet
  root.assertEquals(nullifierRoot, 'Nullifier already set!');

  // set the nullifier to 1
  let [newRoot] = nullifierWitness.computeRootAndKey(Field(1));

  Circuit.asProver(() => {
    nullifierTree.set(expectedNullifier, Field(1));
  });

  return newRoot;
}

function checkVoterEligibility(
  vote: Vote,
  voterData: ReturnType<typeof MerkleMapExtended>,
  publicInput: StateTransition
) {
  let membershipProof = Circuit.witness(MerkleMapWitness, () => {
    return voterData.getWitness(Poseidon.hash(vote.voter.toFields()));
  });
  let weight = Circuit.witness(Field, () => {
    return (voterData.get(Poseidon.hash(vote.voter.toFields())) as any).weight;
  });
  let [root] = membershipProof.computeRootAndKey(
    Poseidon.hash(vote.voter.toFields().concat(weight))
  );
  return root.equals(publicInput.voterDataRoot);
}
