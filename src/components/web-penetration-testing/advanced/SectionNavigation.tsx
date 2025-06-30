
import React, { useState, useEffect } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Sheet, SheetContent, SheetTrigger, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Menu, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavigationItem {
  id: string;
  title: string;
  icon?: React.ReactNode;
}

interface SectionNavigationProps {
  items: NavigationItem[];
  activeSection: string;
  onSectionChange: (sectionId: string) => void;
  className?: string;
}

const SectionNavigation: React.FC<SectionNavigationProps> = ({
  items,
  activeSection,
  onSectionChange,
  className
}) => {
  const [isMobile, setIsMobile] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
      onSectionChange(sectionId);
      setIsOpen(false);
    }
  };

  const NavigationContent = () => (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-cybr-primary mb-4 px-2">
        Quick Navigation
      </h3>
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => scrollToSection(item.id)}
          className={cn(
            "w-full text-left px-3 py-2 rounded-lg text-sm transition-all duration-200 flex items-center gap-2 group",
            activeSection === item.id
              ? "bg-cybr-primary/20 text-cybr-primary border-l-2 border-cybr-primary"
              : "text-cybr-foreground/70 hover:text-cybr-foreground hover:bg-cybr-muted/30"
          )}
        >
          {item.icon && (
            <span className="flex-shrink-0 w-4 h-4">
              {item.icon}
            </span>
          )}
          <span className="flex-1">{item.title}</span>
          <ChevronRight className={cn(
            "w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity",
            activeSection === item.id && "opacity-100"
          )} />
        </button>
      ))}
    </div>
  );

  if (isMobile) {
    return (
      <Sheet open={isOpen} onOpenChange={setIsOpen}>
        <SheetTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className="fixed top-20 right-4 z-50 bg-cybr-card border-cybr-muted"
          >
            <Menu className="h-4 w-4" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="w-80 bg-cybr-card border-cybr-muted">
          <SheetHeader>
            <SheetTitle className="text-cybr-primary">Navigation</SheetTitle>
          </SheetHeader>
          <div className="mt-6">
            <NavigationContent />
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <div className={cn("w-full", className)}>
      <div className="sticky top-20 bg-cybr-card/80 backdrop-blur-lg border border-cybr-muted/40 rounded-lg p-4 z-40 shadow-lg shadow-cybr-primary/5">
        <ScrollArea className="h-[calc(100vh-10rem)] pr-4">
          <NavigationContent />
        </ScrollArea>
      </div>
    </div>
  );
};

export default SectionNavigation;
