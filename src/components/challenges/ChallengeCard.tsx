
import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, FileCode, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface ChallengeCardProps {
  challenge: {
    id: string;
    title: string;
    description: string;
    difficulty: 'easy' | 'medium' | 'hard';
    category: string;
    languages: string[];
    vulnerabilityType?: string;
  };
  onClick: () => void;
  completed?: boolean;
  correct?: boolean;
}

const ChallengeCard: React.FC<ChallengeCardProps> = ({ 
  challenge, 
  onClick,
  completed = false,
  correct = false
}) => {
  const getDifficultyColor = () => {
    switch(challenge.difficulty) {
      case 'easy': return 'bg-green-600/10 text-green-600 border-green-600/30';
      case 'medium': return 'bg-yellow-600/10 text-yellow-600 border-yellow-600/30';
      case 'hard': return 'bg-red-600/10 text-red-600 border-red-600/30';
      default: return 'bg-gray-600/10 text-gray-600 border-gray-600/30';
    }
  };
  
  return (
    <Card 
      className={`bg-cybr-muted/50 border-cybr-primary/20 hover:border-cybr-primary/40 cursor-pointer transition-all hover:-translate-y-1 hover:shadow-md overflow-hidden ${completed ? 'ring-1 ring-inset' : ''} ${correct ? 'ring-green-500/30' : completed ? 'ring-red-500/30' : ''}`}
      onClick={onClick}
    >
      <div className="absolute top-0 right-0 p-2">
        {completed && (
          correct ? 
          <CheckCircle className="w-5 h-5 text-green-500" /> : 
          <XCircle className="w-5 h-5 text-red-500" />
        )}
      </div>
      
      <CardHeader className="pb-2">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-full bg-cybr-primary/10 flex items-center justify-center flex-shrink-0">
            {challenge.vulnerabilityType?.includes('Injection') ? (
              <ShieldAlert className="w-5 h-5 text-cybr-primary" />
            ) : (
              <FileCode className="w-5 h-5 text-cybr-primary" />
            )}
          </div>
          <div>
            <h3 className="font-bold text-lg line-clamp-1">{challenge.title}</h3>
            <p className="text-sm text-cybr-foreground/70 line-clamp-2 mt-1">
              {challenge.description}
            </p>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="py-0">
        <div className="flex flex-wrap gap-1 mb-3 mt-1">
          {challenge.languages.map(language => (
            <Badge key={language} variant="outline" className="bg-cybr-muted border-cybr-primary/30 text-xs py-0">
              {language}
            </Badge>
          ))}
        </div>
      </CardContent>
      
      <CardFooter className="flex justify-between pt-2 pb-3">
        <Badge className={`${getDifficultyColor()} border`}>
          {challenge.difficulty.charAt(0).toUpperCase() + challenge.difficulty.slice(1)}
        </Badge>
        
        <Badge variant="outline" className="bg-cybr-muted/50 text-cybr-foreground/80 border-cybr-muted">
          {challenge.category}
        </Badge>
      </CardFooter>
    </Card>
  );
};

export default ChallengeCard;
