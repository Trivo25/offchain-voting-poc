import { Field, PublicKey, Poseidon, MerkleMap } from 'snarkyjs';
import { Vote } from './sequencer';

export { Nullifier, calculateNullifierRootTransition, calculateVotes };

function Nullifier(publicKey: PublicKey, proposalId: Field) {
  return Poseidon.hash(publicKey.toFields().concat(proposalId));
}

function calculateNullifierRootTransition(
  nullifierTree: MerkleMap,
  votes: Vote[]
) {
  let rootBefore = nullifierTree.getRoot();
  votes.forEach((v) => {
    let key = Nullifier(v.voter, v.proposalId);
    nullifierTree.set(key, Field(1));
  });
  return {
    rootBefore,
    rootAfter: nullifierTree.getRoot(),
  };
}

function calculateVotes(votes: Vote[]) {
  let yes = Field(0);
  let no = Field(0);
  let abstained = Field(0);

  votes.forEach((v) => {
    yes = yes.add(v.yes);
    no = no.add(v.no);
    abstained = abstained.add(v.abstained);
  });

  return {
    yes,
    no,
    abstained,
  };
}
