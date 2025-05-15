
export interface Challenge {
  id: string;
  title: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  category: string;
  languages: string[];
  type: 'comparison' | 'single' | 'multiple-choice';
  vulnerabilityType?: string;
  code?: string;
  answer?: boolean | string | number;
  explanation: string;
  secureCode?: string;
  vulnerableCode?: string;
  options?: string[];
}
