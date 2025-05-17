
import React, { useState, useEffect } from 'react';
import { ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useChallengeContext } from './ChallengeContext';
import { toast } from '@/hooks/use-toast';

// Import the smaller components
import ChallengeHeader from './challenge-view/ChallengeHeader';
import SingleChallenge from './challenge-view/SingleChallenge';
import ComparisonChallenge from './challenge-view/ComparisonChallenge';
import MultipleChoiceChallenge from './challenge-view/MultipleChoiceChallenge';
import ChallengeResult from './challenge-view/ChallengeResult';

interface ChallengeViewProps {
  challenge: any;
  onBack: () => void;
}

const ChallengeView: React.FC<ChallengeViewProps> = ({ challenge, onBack }) => {
  const [selectedAnswer, setSelectedAnswer] = useState<string | number | null>(null);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const { markChallengeAttempt } = useChallengeContext();
  
  // Auto-scroll to top when challenge is opened
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [challenge]);
  
  const isCorrect = () => {
    if (challenge.type === 'single') {
      return selectedAnswer === (challenge.answer ? 'secure' : 'vulnerable');
    } else if (challenge.type === 'multiple-choice') {
      return selectedAnswer === challenge.answer;
    } else {
      return selectedAnswer === challenge.answer;
    }
  };
  
  const handleSubmit = () => {
    if (selectedAnswer === null) {
      toast({
        title: "No answer selected",
        description: "Please select an answer before submitting.",
        variant: "destructive"
      });
      return;
    }
    
    setIsSubmitted(true);
    markChallengeAttempt(challenge.id, isCorrect());
  };
  
  return (
    <div className="space-y-6">
      <Button 
        variant="ghost" 
        onClick={onBack}
        className="flex items-center gap-2 mb-4 hover:bg-cybr-muted/30"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Challenges
      </Button>
      
      <div className="card p-6">
        <ChallengeHeader 
          title={challenge.title}
          difficulty={challenge.difficulty}
          category={challenge.category}
          vulnerabilityType={challenge.vulnerabilityType}
          description={challenge.description}
        />
        
        {challenge.type === 'single' && (
          <SingleChallenge
            challenge={challenge}
            selectedAnswer={selectedAnswer}
            setSelectedAnswer={setSelectedAnswer}
            isSubmitted={isSubmitted}
          />
        )}
        
        {challenge.type === 'comparison' && (
          <ComparisonChallenge
            challenge={challenge}
            selectedAnswer={selectedAnswer}
            setSelectedAnswer={setSelectedAnswer}
            isSubmitted={isSubmitted}
          />
        )}
        
        {challenge.type === 'multiple-choice' && (
          <MultipleChoiceChallenge
            challenge={challenge}
            selectedAnswer={selectedAnswer}
            setSelectedAnswer={setSelectedAnswer}
            isSubmitted={isSubmitted}
          />
        )}
        
        {!isSubmitted ? (
          <Button 
            onClick={handleSubmit} 
            disabled={selectedAnswer === null}
            className="w-full md:w-auto"
          >
            Submit Answer
          </Button>
        ) : (
          <ChallengeResult
            isCorrect={isCorrect()}
            explanation={challenge.explanation}
            onBack={onBack}
          />
        )}
      </div>
    </div>
  );
};

export default ChallengeView;
