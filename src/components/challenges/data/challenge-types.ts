
export interface Challenge {
  id: string;
  title: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  category: string;
  languages: string[];
  type: 'comparison' | 'single';
  vulnerabilityType?: string;
  code?: string;
  answer?: boolean | string;
  explanation: string;
  secureCode?: string;
  vulnerableCode?: string;
}
