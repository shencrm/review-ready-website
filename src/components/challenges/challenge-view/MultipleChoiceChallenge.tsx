
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';

interface MultipleChoiceChallengeProps {
  challenge: any;
  selectedAnswer: string | number | null;
  setSelectedAnswer: (value: string | number) => void;
  isSubmitted: boolean;
}

const MultipleChoiceChallenge: React.FC<MultipleChoiceChallengeProps> = ({ 
  challenge, 
  selectedAnswer, 
  setSelectedAnswer, 
  isSubmitted 
}) => {
  return (
    <div className="mb-8">
      <CodeExample 
        language={challenge.languages[0].toLowerCase()}
        code={challenge.code}
        title={`Review this code for security issues`}
      />
      
      <div className="mt-6 mb-4">
        <h3 className="text-xl font-bold mb-4">Select the correct answer:</h3>
        
        <RadioGroup 
          value={selectedAnswer?.toString() || ''} 
          onValueChange={(value) => setSelectedAnswer(parseInt(value))} 
          className="space-y-3"
        >
          {challenge.options?.map((option: string, index: number) => (
            <div key={index} className="flex items-center space-x-3">
              <RadioGroupItem value={index.toString()} id={`option-${index}`} disabled={isSubmitted} />
              <label htmlFor={`option-${index}`} className="cursor-pointer">
                {option}
              </label>
            </div>
          ))}
        </RadioGroup>
      </div>
    </div>
  );
};

export default MultipleChoiceChallenge;
