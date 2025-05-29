
import React from 'react';
import CSRFIntroduction from './csrf/CSRFIntroduction';
import CSRFAttackTypes from './csrf/CSRFAttackTypes';
import CSRFExploitationPhases from './csrf/CSRFExploitationPhases';
import CSRFPreventionStrategies from './csrf/CSRFPreventionStrategies';
import CSRFTestingTools from './csrf/CSRFTestingTools';

const CSRF: React.FC = () => {
  return (
    <section id="csrf" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">
        Cross-Site Request Forgery (CSRF)
      </h3>
      
      <div className="space-y-8">
        <CSRFIntroduction />
        <CSRFAttackTypes />
        <CSRFExploitationPhases />
        <CSRFPreventionStrategies />
        <CSRFTestingTools />
      </div>
    </section>
  );
};

export default CSRF;
