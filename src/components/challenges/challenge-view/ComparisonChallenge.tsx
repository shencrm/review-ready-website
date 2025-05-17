
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';

interface ComparisonChallengeProps {
  challenge: any;
  selectedAnswer: string | number | null;
  setSelectedAnswer: (value: string | number) => void;
  isSubmitted: boolean;
}

const ComparisonChallenge: React.FC<ComparisonChallengeProps> = ({ 
  challenge, 
  selectedAnswer, 
  setSelectedAnswer, 
  isSubmitted 
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <div>
        <CodeExample 
          language={challenge.languages[0].toLowerCase()}
          code={challenge.secureCode}
          title="Implementation A"
        />
      </div>
      <div>
        <CodeExample 
          language={challenge.languages[0].toLowerCase()}
          code={challenge.vulnerableCode}
          title="Implementation B"
        />
      </div>
      
      <div className="lg:col-span-2 mt-4">
        <h3 className="text-xl font-bold mb-4">Which implementation is secure?</h3>
        
        <RadioGroup 
          value={selectedAnswer?.toString() || ''} 
          onValueChange={setSelectedAnswer} 
          className="space-y-3"
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="secure" id="a-secure" disabled={isSubmitted} />
            <label htmlFor="a-secure" className="cursor-pointer">
              Implementation A is secure
            </label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="vulnerable" id="b-secure" disabled={isSubmitted} />
            <label htmlFor="b-secure" className="cursor-pointer">
              Implementation B is secure
            </label>
          </div>
        </RadioGroup>
      </div>
    </div>
  );
};

export default ComparisonChallenge;
