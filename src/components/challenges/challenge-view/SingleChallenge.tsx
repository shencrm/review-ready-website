
import React from 'react';
import { Check, AlertTriangle } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';

interface SingleChallengeProps {
  challenge: any;
  selectedAnswer: string | number | null;
  setSelectedAnswer: (value: string | number) => void;
  isSubmitted: boolean;
}

const SingleChallenge: React.FC<SingleChallengeProps> = ({ 
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
        <h3 className="text-xl font-bold mb-4">Is this code secure or vulnerable?</h3>
        
        <RadioGroup 
          value={selectedAnswer?.toString() || ''} 
          onValueChange={setSelectedAnswer} 
          className="space-y-3"
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="secure" id="secure" disabled={isSubmitted} />
            <label htmlFor="secure" className="flex items-center cursor-pointer">
              <div className="w-6 h-6 rounded-full bg-green-500/20 flex items-center justify-center mr-2">
                <Check className="w-4 h-4 text-green-500" />
              </div>
              <span>This code is secure</span>
            </label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="vulnerable" id="vulnerable" disabled={isSubmitted} />
            <label htmlFor="vulnerable" className="flex items-center cursor-pointer">
              <div className="w-6 h-6 rounded-full bg-red-500/20 flex items-center justify-center mr-2">
                <AlertTriangle className="w-4 h-4 text-red-500" />
              </div>
              <span>This code is vulnerable</span>
            </label>
          </div>
        </RadioGroup>
      </div>
    </div>
  );
};

export default SingleChallenge;
