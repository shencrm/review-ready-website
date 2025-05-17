
import React from 'react';
import CodeExample from '@/components/CodeExample';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { ScrollArea } from '@/components/ui/scroll-area';

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
      {challenge.code && (
        <CodeExample 
          language={challenge.languages[0].toLowerCase()}
          code={challenge.code}
          title={`Review this code for security issues`}
        />
      )}
      
      <div className="mt-6 mb-4">
        <h3 className="text-xl font-bold mb-4">Select the correct answer:</h3>
        
        <ScrollArea className="max-h-[400px] pr-4">
          <RadioGroup 
            value={selectedAnswer?.toString() || ''} 
            onValueChange={(value) => setSelectedAnswer(parseInt(value))} 
            className="space-y-3"
          >
            {challenge.options?.map((option: string, index: number) => {
              const isCorrect = isSubmitted && index === challenge.answer;
              const isWrong = isSubmitted && selectedAnswer === index && index !== challenge.answer;
              
              return (
                <div 
                  key={index} 
                  className={`flex items-center space-x-3 py-2 px-3 rounded-md ${
                    isCorrect ? 'bg-green-100 dark:bg-green-900/20 border border-green-300 dark:border-green-700' :
                    isWrong ? 'bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700' :
                    ''
                  }`}
                >
                  <RadioGroupItem 
                    value={index.toString()} 
                    id={`option-${index}`} 
                    disabled={isSubmitted} 
                    className={isCorrect ? 'text-green-500 border-green-500' : isWrong ? 'text-red-500 border-red-500' : ''}
                  />
                  <label 
                    htmlFor={`option-${index}`} 
                    className={`cursor-pointer ${
                      isCorrect ? 'text-green-700 dark:text-green-300 font-medium' : 
                      isWrong ? 'text-red-700 dark:text-red-300 font-medium' : ''
                    }`}
                  >
                    {option}
                    {isCorrect && (
                      <span className="ml-2 text-green-600 dark:text-green-400 text-sm">(Correct)</span>
                    )}
                    {isWrong && (
                      <span className="ml-2 text-red-600 dark:text-red-400 text-sm">(Incorrect)</span>
                    )}
                  </label>
                </div>
              );
            })}
          </RadioGroup>
        </ScrollArea>
      </div>
    </div>
  );
};

export default MultipleChoiceChallenge;
