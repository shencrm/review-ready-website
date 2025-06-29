
import React from 'react';
import { Bug } from 'lucide-react';
import RaceConditionsIntroduction from './race-conditions/RaceConditionsIntroduction';
import RaceConditionsAttackVectors from './race-conditions/RaceConditionsAttackVectors';
import RaceConditionsExploitation from './race-conditions/RaceConditionsExploitation';
import RaceConditionsCodeExamples from './race-conditions/RaceConditionsCodeExamples';
import RaceConditionsTesting from './race-conditions/RaceConditionsTesting';
import RaceConditionsPrevention from './race-conditions/RaceConditionsPrevention';

const RaceConditions: React.FC = () => {
  return (
    <section id="race" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Race Conditions</h3>
      
      <RaceConditionsIntroduction />
      <RaceConditionsAttackVectors />
      <RaceConditionsExploitation />
      <RaceConditionsCodeExamples />
      <RaceConditionsTesting />
      <RaceConditionsPrevention />
    </section>
  );
};

export default RaceConditions;
