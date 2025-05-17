
import React from 'react';
import { Badge } from '@/components/ui/badge';

interface ChallengeHeaderProps {
  title: string;
  difficulty: string;
  category: string;
  vulnerabilityType?: string;
  description: string;
}

const ChallengeHeader: React.FC<ChallengeHeaderProps> = ({
  title,
  difficulty,
  category,
  vulnerabilityType,
  description
}) => {
  const getDifficultyColor = () => {
    switch(difficulty) {
      case 'easy': return 'bg-green-600/10 text-green-600 border-green-600/30';
      case 'medium': return 'bg-yellow-600/10 text-yellow-600 border-yellow-600/30';
      case 'hard': return 'bg-red-600/10 text-red-600 border-red-600/30';
      default: return 'bg-gray-600/10 text-gray-600 border-gray-600/30';
    }
  };
  
  return (
    <>
      <div className="flex flex-wrap gap-3 mb-6 items-center justify-between">
        <h2 className="text-2xl font-bold text-cybr-primary">{title}</h2>
        <div className="flex gap-2 flex-wrap">
          <Badge className={getDifficultyColor()}>
            {difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
          </Badge>
          <Badge variant="outline" className="bg-cybr-muted/50 border-cybr-muted">
            {category}
          </Badge>
          {vulnerabilityType && (
            <Badge variant="outline" className="bg-cybr-accent/10 text-cybr-accent border-cybr-accent/30">
              {vulnerabilityType}
            </Badge>
          )}
        </div>
      </div>
      
      <p className="mb-8 text-lg">{description}</p>
    </>
  );
};

export default ChallengeHeader;
