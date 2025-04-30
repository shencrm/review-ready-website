
import React from 'react';

interface SecurityCardProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  className?: string;
}

const SecurityCard: React.FC<SecurityCardProps> = ({ title, description, icon, className }) => {
  return (
    <div className={`card ${className}`}>
      {icon && <div className="mb-4 text-cybr-primary">{icon}</div>}
      <h3 className="text-xl font-bold mb-3 text-cybr-foreground">{title}</h3>
      <p className="text-cybr-foreground/80">{description}</p>
    </div>
  );
};

export default SecurityCard;
