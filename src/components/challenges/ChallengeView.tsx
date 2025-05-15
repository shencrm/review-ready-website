
import React, { useState } from 'react';
import { ArrowLeft, Check, X, AlertTriangle, ThumbsUp, FileCode } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import { Button } from '@/components/ui/button';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardFooter, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { 
  RadioGroup, 
  RadioGroupItem 
} from '@/components/ui/radio-group';
import { Badge } from '@/components/ui/badge';
import { useChallengeContext } from './ChallengeContext';
import { toast } from '@/hooks/use-toast';

interface ChallengeViewProps {
  challenge: any;
  onBack: () => void;
}

const ChallengeView: React.FC<ChallengeViewProps> = ({ challenge, onBack }) => {
  const [selectedAnswer, setSelectedAnswer] = useState<string | number | null>(null);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const { markChallengeAttempt } = useChallengeContext();
  
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
  
  const getDifficultyColor = () => {
    switch(challenge.difficulty) {
      case 'easy': return 'bg-green-600/10 text-green-600 border-green-600/30';
      case 'medium': return 'bg-yellow-600/10 text-yellow-600 border-yellow-600/30';
      case 'hard': return 'bg-red-600/10 text-red-600 border-red-600/30';
      default: return 'bg-gray-600/10 text-gray-600 border-gray-600/30';
    }
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
        <div className="flex flex-wrap gap-3 mb-6 items-center justify-between">
          <h2 className="text-2xl font-bold text-cybr-primary">{challenge.title}</h2>
          <div className="flex gap-2 flex-wrap">
            <Badge className={getDifficultyColor()}>
              {challenge.difficulty.charAt(0).toUpperCase() + challenge.difficulty.slice(1)}
            </Badge>
            <Badge variant="outline" className="bg-cybr-muted/50 border-cybr-muted">
              {challenge.category}
            </Badge>
            {challenge.vulnerabilityType && (
              <Badge variant="outline" className="bg-cybr-accent/10 text-cybr-accent border-cybr-accent/30">
                {challenge.vulnerabilityType}
              </Badge>
            )}
          </div>
        </div>
        
        <p className="mb-8 text-lg">{challenge.description}</p>
        
        {challenge.type === 'single' && (
          // Single code review
          <div className="mb-8">
            <CodeExample 
              language={challenge.languages[0].toLowerCase()}
              code={challenge.code}
              title={`Review this code for security issues`}
            />
            
            <div className="mt-6 mb-4">
              <h3 className="text-xl font-bold mb-4">Is this code secure or vulnerable?</h3>
              
              <RadioGroup value={selectedAnswer?.toString() || ''} onValueChange={setSelectedAnswer} className="space-y-3">
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
        )}
        
        {challenge.type === 'comparison' && (
          // Comparison code review
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
              
              <RadioGroup value={selectedAnswer?.toString() || ''} onValueChange={setSelectedAnswer} className="space-y-3">
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
        )}
        
        {challenge.type === 'multiple-choice' && (
          // Multiple choice question
          <div className="mb-8">
            <CodeExample 
              language={challenge.languages[0].toLowerCase()}
              code={challenge.code}
              title={`Review this code for security issues`}
            />
            
            <div className="mt-6 mb-4">
              <h3 className="text-xl font-bold mb-4">Select the correct answer:</h3>
              
              <RadioGroup value={selectedAnswer?.toString() || ''} onValueChange={(value) => setSelectedAnswer(parseInt(value))} className="space-y-3">
                {challenge.options?.map((option, index) => (
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
          <Card className={isCorrect() ? 'border-green-500 bg-green-500/10' : 'border-red-500 bg-red-500/10'}>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                {isCorrect() ? (
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
                {challenge.explanation}
              </CardDescription>
            </CardHeader>
            <CardFooter className="pt-2">
              <Button variant="outline" onClick={onBack}>
                Try Another Challenge
              </Button>
            </CardFooter>
          </Card>
        )}
      </div>
    </div>
  );
};

export default ChallengeView;
