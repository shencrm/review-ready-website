
import React, { createContext, useState, useContext, ReactNode } from 'react';
import { challenges } from './data';
import { Challenge } from './data/challenge-types';

interface ChallengeProgress {
  [challengeId: string]: {
    completed: boolean;
    correct: boolean;
    attemptCount: number;
  };
}

interface ChallengeContextType {
  allChallenges: Challenge[];
  currentChallenge: Challenge | null;
  selectedCategory: string;
  selectedLanguage: string;
  selectedDifficulty: string;
  progress: ChallengeProgress;
  setCurrentChallenge: (challenge: Challenge | null) => void;
  setSelectedCategory: (category: string) => void;
  setSelectedLanguage: (language: string) => void;
  setSelectedDifficulty: (difficulty: string) => void;
  markChallengeAttempt: (challengeId: string, correct: boolean) => void;
  filteredChallenges: Challenge[];
}

const ChallengeContext = createContext<ChallengeContextType | undefined>(undefined);

export const ChallengeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [currentChallenge, setCurrentChallenge] = useState<Challenge | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>('all');
  const [progress, setProgress] = useState<ChallengeProgress>({});
  const allChallenges = challenges as Challenge[];

  const markChallengeAttempt = (challengeId: string, correct: boolean) => {
    setProgress(prevProgress => {
      const challengeProgress = prevProgress[challengeId] || { completed: false, correct: false, attemptCount: 0 };
      return {
        ...prevProgress,
        [challengeId]: {
          completed: true,
          correct: correct,
          attemptCount: challengeProgress.attemptCount + 1
        }
      };
    });
  };

  const filteredChallenges = allChallenges.filter(challenge => {
    const categoryMatch = selectedCategory === 'all' || challenge.category.toLowerCase() === selectedCategory;
    const languageMatch = selectedLanguage === 'all' || challenge.languages.some(lang => lang.toLowerCase() === selectedLanguage);
    const difficultyMatch = selectedDifficulty === 'all' || challenge.difficulty === selectedDifficulty;
    
    return categoryMatch && languageMatch && difficultyMatch;
  });

  return (
    <ChallengeContext.Provider value={{
      allChallenges,
      currentChallenge,
      selectedCategory,
      selectedLanguage,
      selectedDifficulty,
      progress,
      setCurrentChallenge,
      setSelectedCategory,
      setSelectedLanguage,
      setSelectedDifficulty,
      markChallengeAttempt,
      filteredChallenges
    }}>
      {children}
    </ChallengeContext.Provider>
  );
};

export const useChallengeContext = () => {
  const context = useContext(ChallengeContext);
  if (context === undefined) {
    throw new Error('useChallengeContext must be used within a ChallengeProvider');
  }
  return context;
};
