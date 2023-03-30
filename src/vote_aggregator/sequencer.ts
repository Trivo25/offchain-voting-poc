import {
  PublicKey,
  Struct,
  Field,
  MerkleMap,
  Signature,
  UInt32,
  MerkleMapWitness,
  Poseidon,
  isReady,
  PrivateKey,
} from 'snarkyjs';

import express from 'express';

export {
  VoterData,
  Vote,
  Proposal,
  StateTransition,
  VotingPeriod,
  Voting,
  MerkleMapExtended,
};

//await isReady;

class Proposal extends Struct({
  title: String,
  id: Field,
  // we can add as many or as less options as we want
  yes: Field,
  no: Field,
  abstained: Field,
}) {}

class StateTransition extends Struct({
  voterDataRoot: Field, // this never changes
  nullifier: {
    before: Field,
    after: Field,
  },
  proposalId: Field,
  result: {
    before: {
      yes: Field,
      no: Field,
      abstained: Field,
    },
    after: { yes: Field, no: Field, abstained: Field },
  },
}) {}

class VotingPeriod extends Struct({
  electionPeriod: {
    start: UInt32,
    end: UInt32,
  },
  challengingPeriod: {
    start: UInt32,
    end: UInt32,
  },
}) {}

class VoterData extends Struct({
  publicKey: PublicKey,
  weight: Field,
}) {
  hash(): Field {
    return Poseidon.hash(this.publicKey.toFields().concat(this.weight));
  }

  toJSON() {
    return {
      publicKey: this.publicKey.toBase58(),
      weight: this.weight.toString(),
    };
  }
}

type JSONVote = {
  voter: string;
  authorization: {
    r: string;
    s: string;
  };
  voterDataRoot: string;
  yes: string;
  no: string;
  abstained: string;
  proposalId: string;
};

function validateJSONVote(json: unknown): json is JSONVote {
  // this is very sloppy
  return (
    typeof json === 'object' &&
    json !== null &&
    'voter' in json &&
    'authorization' in json &&
    'voterDataRoot' in json &&
    'choice' in json &&
    'proposalId' in json
  );
}

class Vote extends Struct({
  voter: PublicKey,
  authorization: Signature,
  voterDataRoot: Field,
  proposalId: Field,
  yes: Field,
  no: Field,
  abstained: Field,
}) {
  fromJSON(json: JSONVote): Vote {
    return new Vote({
      voter: PublicKey.fromBase58(json.voter),
      authorization: Signature.fromJSON(json.authorization),
      voterDataRoot: Field(this.voterDataRoot),
      yes: Field(json.yes),
      no: Field(json.no),
      abstained: Field(json.abstained),
      proposalId: Field(json.proposalId),
    });
  }

  verifySignature(publicKey: PublicKey) {
    return this.authorization.verify(publicKey, [
      this.yes,
      this.no,
      this.abstained,
      this.proposalId,
      this.voterDataRoot,
    ]);
  }
}

// just a tiny helper function
function MerkleMapExtended<
  V extends {
    hash(): Field;
    toJSON(): any;
  }
>() {
  let merkleMap = new MerkleMap();
  let map = new Map<string, V>();

  return {
    get(key: Field): V {
      return map.get(key.toString())!;
    },
    set(key: Field, value: V) {
      map.set(key.toString(), value);
      merkleMap.set(key, value.hash());
    },
    getRoot(): Field {
      return merkleMap.getRoot();
    },
    getWitness(key: Field): MerkleMapWitness {
      return merkleMap.getWitness(key);
    },
    flat() {
      let leaves = [...map.keys()].map((key, i) => {
        let entry = map.get(key)!;
        return {
          i,
          key,
          data: { ...entry.toJSON(), hash: entry.hash().toString() },
        };
      });
      return {
        meta: {
          root: merkleMap.getRoot().toString(),
          height: merkleMap.tree.height.toString(),
          leafCount: merkleMap.tree.leafCount.toString(),
        },
        leaves,
      };
    },
  };
}

const PORT = 3000;

function Voting({
  proposalTitle,
  proposalId,
  feePayer,
  electionPeriod,
  challengingPeriod,
  voterData,
}: {
  proposalTitle: string;
  proposalId: string;
  feePayer: PrivateKey;
  electionPeriod: {
    start: UInt32;
    end: UInt32;
  };
  challengingPeriod: {
    start: UInt32;
    end: UInt32;
  };
  voterData: { publicKey: PublicKey; weight: Field }[];
}) {
  let acceptingVotes = true;

  const VoterDataTree = MerkleMapExtended<VoterData>();

  // pretty naive but will do for now
  voterData.forEach((voter) => {
    // voters are indexed by the hash of their public key
    VoterDataTree.set(
      Poseidon.hash(voter.publicKey.toFields()),
      new VoterData(voter)
    );
  });

  const NullifierTree = new MerkleMap();

  // this will serve as our mem pool, as we don't have to aggregate all votes directly
  const VotePool: Vote[] = [];

  return {
    async deploy() {},
    async listen() {
      const app = express();
      app.use(express.json());

      app.post('/castVote', (req, res) => {
        if (!acceptingVotes) {
          res.status(400).json({
            reason: 'Voting period is over - not accepting more votes.',
          });
        }
        console.debug('received a vote');
        let jsonVote = req.body;
        if (validateJSONVote(jsonVote)) {
          let isValidOrError = validateVote(jsonVote, VotePool, voterData);
          if (typeof isValidOrError === 'undefined') {
            res.status(200).send();
          } else {
            res.status(400).json({
              reason: isValidOrError as string,
              data: jsonVote,
            });
          }
        } else {
          res.status(400).json({
            reason: 'Invalid vote structure.',
            data: jsonVote,
          });
        }
      });

      app.post('/proposal', (req, res) => {
        res.status(200).json({
          proposalTitle,
          proposalId,
        });
      });

      app.post('/tree', (req, res) => {
        res.status(200).json(VoterDataTree.flat());
      });

      // this triggers tallying but just for now
      app.post('tally', (req, res) => {
        acceptingVotes = false;
        // TODO
      });

      app.listen(PORT, () => {
        console.log(
          `[server]: Vote sequencer running at http://localhost:${PORT}`
        );
      });
    },
  };
}

function validateVote(
  jsonVote: JSONVote,
  votePool: Vote[],
  voterData: { publicKey: PublicKey }[]
): undefined | string {
  let vote = Vote.fromJSON(jsonVote);

  let isVoter = voterData.find((v) =>
    v.publicKey.equals(vote.voter).toBoolean()
  );

  if (!isVoter) {
    return 'Voter is not part of list of eligible voters.';
  }

  if (!vote.yes.add(vote.no).add(vote.abstained).equals(1).toBoolean()) {
    return 'You can only cast one vote!';
  }

  let payload = vote.voter
    .toFields()
    .concat([vote.yes, vote.no, vote.abstained, vote.voterDataRoot]);
  let isValid = vote.authorization.verify(vote.voter, payload).toBoolean();

  if (isValid) {
    // we check that there are no multiple votes from the same voter in the pool - just some pre-checking to prevent spam
    let exists = votePool.find((v) => v.voter.equals(vote.voter));
    if (exists) {
      votePool.push(vote as Vote);
      return;
    }
    return 'Vote already casted.';
  }
  return 'Vote is not valid.';
}

// can use this to schedule the tallying phase
function runIn(ms: number, cb: () => void) {
  setTimeout(cb, ms);
}

function aggregateVotes(votePool: Vote[]) {}
