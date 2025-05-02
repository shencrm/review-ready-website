
import React from 'react';

interface SecurityCardProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  className?: string;
  severity?: 'high' | 'medium' | 'low';
}

const SecurityCard: React.FC<SecurityCardProps> = ({ 
  title, 
  description, 
  icon, 
  className,
  severity = 'medium' 
}) => {
  const getSeverityColor = () => {
    switch (severity) {
      case 'high':
        return 'border-red-500';
      case 'medium':
        return 'border-yellow-500';
      case 'low':
        return 'border-green-500';
      default:
        return 'border-cybr-muted';
    }
  };

  return (
    <div className={`card border-l-4 ${getSeverityColor()} ${className}`}>
      <div className="flex items-start">
        {icon && <div className="mr-4 text-cybr-primary">{icon}</div>}
        <div>
          <h3 className="text-xl font-bold mb-2 text-cybr-foreground">{title}</h3>
          <p className="text-cybr-foreground/80">{description}</p>
        </div>
      </div>
    </div>
  );
};

export default SecurityCard;
