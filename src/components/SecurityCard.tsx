
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

  const getSeverityLabel = () => {
    switch (severity) {
      case 'high':
        return 'High Risk';
      case 'medium':
        return 'Medium Risk';
      case 'low':
        return 'Low Risk';
      default:
        return 'Risk Level';
    }
  };

  const getSeverityBadgeColor = () => {
    switch (severity) {
      case 'high':
        return 'bg-red-500 text-white';
      case 'medium':
        return 'bg-yellow-500 text-black';
      case 'low':
        return 'bg-green-500 text-white';
      default:
        return 'bg-cybr-muted text-cybr-foreground';
    }
  };

  return (
    <div className={`card border-l-4 ${getSeverityColor()} ${className}`}>
      <div className="flex items-start">
        {icon && <div className="mr-4 text-cybr-primary">{icon}</div>}
        <div className="flex-1">
          <div className="flex justify-between items-center mb-2">
            <h3 className="text-xl font-bold text-cybr-foreground">{title}</h3>
            <span className={`text-xs px-2 py-1 rounded-full ${getSeverityBadgeColor()}`}>
              {getSeverityLabel()}
            </span>
          </div>
          <p className="text-cybr-foreground/80">{description}</p>
        </div>
      </div>
    </div>
  );
};

export default SecurityCard;
