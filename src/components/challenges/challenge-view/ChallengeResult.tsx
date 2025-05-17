
import React from 'react';
import { ThumbsUp, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter,
} from '@/components/ui/card';

interface ChallengeResultProps {
  isCorrect: boolean;
  explanation: string;
  onBack: () => void;
}

const ChallengeResult: React.FC<ChallengeResultProps> = ({ 
  isCorrect, 
  explanation, 
  onBack 
}) => {
  return (
    <Card className={isCorrect ? 'border-green-500 bg-green-500/10' : 'border-red-500 bg-red-500/10'}>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          {isCorrect ? (
            <>
              <div className="w-8 h-8 rounded-full bg-green-500 flex items-center justify-center">
                <ThumbsUp className="w-4 h-4 text-white" />
              </div>
              <CardTitle className="text-green-500">Correct!</CardTitle>
            </>
          ) : (
            <>
              <div className="w-8 h-8 rounded-full bg-red-500 flex items-center justify-center">
                <X className="w-4 h-4 text-white" />
              </div>
              <CardTitle className="text-red-500">Not Quite Right</CardTitle>
            </>
          )}
        </div>
        <CardDescription className="text-base mt-1">
          {explanation}
        </CardDescription>
      </CardHeader>
      <CardFooter className="pt-2">
        <Button variant="outline" onClick={onBack}>
          Try Another Challenge
        </Button>
      </CardFooter>
    </Card>
  );
};

export default ChallengeResult;
