
import React, { useState } from 'react';
import { useChallengeContext } from './ChallengeContext';
import { SearchIcon, Filter, CheckCircle, XCircle, Activity } from 'lucide-react';
import { categories, languages, difficulties } from './challengeData';
import ChallengeCard from './ChallengeCard';
import ChallengeView from './ChallengeView';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select';

const ChallengeExplorer: React.FC = () => {
  const {
    filteredChallenges,
    currentChallenge,
    setCurrentChallenge,
    selectedCategory,
    setSelectedCategory,
    selectedLanguage,
    setSelectedLanguage,
    selectedDifficulty,
    setSelectedDifficulty,
    progress
  } = useChallengeContext();
  
  const [searchTerm, setSearchTerm] = useState('');
  
  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  };
  
  const handleReset = () => {
    setSearchTerm('');
    setSelectedCategory('all');
    setSelectedLanguage('all');
    setSelectedDifficulty('all');
  };
  
  const filteredBySearch = filteredChallenges.filter(challenge => 
    challenge.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    challenge.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    challenge.vulnerabilityType?.toLowerCase().includes(searchTerm.toLowerCase()) || 
    false
  );
  
  const handleBackToExplorer = () => {
    setCurrentChallenge(null);
  };
  
  // Calculate counts
  const completedCount = Object.values(progress).filter(p => p.completed).length;
  const correctCount = Object.values(progress).filter(p => p.correct).length;
  
  if (currentChallenge) {
    return <ChallengeView challenge={currentChallenge} onBack={handleBackToExplorer} />;
  }
  
  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="card bg-gradient-to-br from-cybr-muted to-cybr-muted/50 p-4">
          <div className="flex items-center mb-1">
            <Activity className="w-5 h-5 mr-2 text-cybr-primary" />
            <h3 className="font-bold">Total Challenges</h3>
          </div>
          <p className="text-2xl font-bold">{filteredChallenges.length}</p>
        </div>
        
        <div className="card bg-gradient-to-br from-cybr-muted to-cybr-muted/50 p-4">
          <div className="flex items-center mb-1">
            <CheckCircle className="w-5 h-5 mr-2 text-green-500" />
            <h3 className="font-bold">Correct Answers</h3>
          </div>
          <p className="text-2xl font-bold">{correctCount}</p>
        </div>
        
        <div className="card bg-gradient-to-br from-cybr-muted to-cybr-muted/50 p-4">
          <div className="flex items-center mb-1">
            <XCircle className="w-5 h-5 mr-2 text-red-500" />
            <h3 className="font-bold">Attempted</h3>
          </div>
          <p className="text-2xl font-bold">{completedCount}</p>
        </div>
      </div>
      
      <div className="card p-6">
        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <div className="relative flex-grow">
            <SearchIcon className="absolute left-3 top-2.5 h-4 w-4 text-cybr-foreground/50" />
            <Input
              placeholder="Search challenges..."
              className="pl-10"
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          
          <div className="flex flex-col sm:flex-row gap-3">
            <Select 
              value={selectedCategory} 
              onValueChange={setSelectedCategory}
            >
              <SelectTrigger className="w-full sm:w-[180px] bg-cybr-muted/30">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {categories.filter(cat => cat !== 'All').map(category => (
                  <SelectItem key={category} value={category.toLowerCase()}>
                    {category}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            
            <Select 
              value={selectedLanguage} 
              onValueChange={setSelectedLanguage}
            >
              <SelectTrigger className="w-full sm:w-[180px] bg-cybr-muted/30">
                <SelectValue placeholder="Language" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Languages</SelectItem>
                {languages.filter(lang => lang !== 'All').map(language => (
                  <SelectItem key={language} value={language.toLowerCase()}>
                    {language}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            
            <Select 
              value={selectedDifficulty} 
              onValueChange={setSelectedDifficulty}
            >
              <SelectTrigger className="w-full sm:w-[180px] bg-cybr-muted/30">
                <SelectValue placeholder="Difficulty" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Levels</SelectItem>
                <SelectItem value="easy">Easy</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="hard">Hard</SelectItem>
              </SelectContent>
            </Select>
            
            <Button 
              onClick={handleReset}
              variant="outline" 
              className="bg-cybr-muted/30"
            >
              <Filter className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
        
        {filteredBySearch.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredBySearch.map(challenge => (
              <ChallengeCard 
                key={challenge.id} 
                challenge={challenge} 
                onClick={() => setCurrentChallenge(challenge)}
                completed={progress[challenge.id]?.completed || false}
                correct={progress[challenge.id]?.correct || false}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-xl text-cybr-foreground/60">No challenges found matching your filters.</p>
            <Button 
              onClick={handleReset}
              variant="link" 
              className="mt-2 text-cybr-primary"
            >
              Reset filters
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};

export default ChallengeExplorer;
