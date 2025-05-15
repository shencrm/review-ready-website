
import { Challenge } from './challenge-types';

export const businessLogicFlawsChallenges: Challenge[] = [
  {
    id: 'business-logic-1',
    title: 'E-commerce Discount Exploitation',
    description: 'This Node.js function applies discounts on an e-commerce order. What business logic vulnerability is present?',
    difficulty: 'medium',
    category: 'Business Logic Flaws',
    languages: ['JavaScript', 'Node.js'],
    type: 'single',
    vulnerabilityType: 'Discount Code Abuse',
    code: `/**
 * Apply discount codes to an order
 * @param {Object} order - The order object with items and total
 * @param {Array<string>} discountCodes - Array of discount codes
 * @returns {Object} Updated order with discounts applied
 */
function applyDiscounts(order, discountCodes) {
  let totalDiscount = 0;
  const appliedCodes = [];
  
  // Process each discount code
  for (const code of discountCodes) {
    // Get discount details from database (simplified)
    const discount = getDiscountFromDatabase(code);
    
    if (!discount) {
      console.log(\`Invalid discount code: \${code}\`);
      continue;
    }
    
    // Check if discount is still valid
    if (new Date() > new Date(discount.expiryDate)) {
      console.log(\`Expired discount code: \${code}\`);
      continue;
    }
    
    // Apply percentage discount
    if (discount.type === 'percentage') {
      const discountAmount = (order.total * discount.value) / 100;
      totalDiscount += discountAmount;
      appliedCodes.push({
        code: code,
        type: 'percentage',
        value: discount.value,
        amount: discountAmount
      });
    } 
    // Apply fixed amount discount
    else if (discount.type === 'fixed') {
      totalDiscount += discount.value;
      appliedCodes.push({
        code: code,
        type: 'fixed',
        value: discount.value,
        amount: discount.value
      });
    }
    
    console.log(\`Applied discount code: \${code}, amount: \${totalDiscount}\`);
  }
  
  // Calculate new total
  const discountedTotal = Math.max(0, order.total - totalDiscount);
  
  return {
    ...order,
    discounts: appliedCodes,
    totalDiscount: totalDiscount,
    discountedTotal: discountedTotal
  };
}

// Mock function to get discount from database
function getDiscountFromDatabase(code) {
  const discounts = {
    'WELCOME10': { type: 'percentage', value: 10, expiryDate: '2023-12-31' },
    'SAVE20': { type: 'percentage', value: 20, expiryDate: '2023-12-31' },
    'FLAT50': { type: 'fixed', value: 50, expiryDate: '2023-12-31' }
  };
  
  return discounts[code];
}

// Example usage
const order = {
  id: '12345',
  items: [
    { id: 'item1', name: 'Product 1', price: 100, quantity: 1 },
    { id: 'item2', name: 'Product 2', price: 50, quantity: 2 }
  ],
  total: 200
};

const updatedOrder = applyDiscounts(order, ['WELCOME10', 'SAVE20', 'FLAT50']);
console.log(updatedOrder);`,
    answer: false,
    explanation: "This code has a serious business logic flaw: it allows multiple discount codes to be applied cumulatively without any restrictions, enabling discount stacking. An attacker could apply multiple percentage discounts and fixed-value discounts to drastically reduce or eliminate the cost of their order. For example, applying WELCOME10 (10% off), SAVE20 (20% off), and FLAT50 ($50 off) on a $200 order results in a $110 discount, reducing the price by 55%. The code should implement rules like: 1) Limit the number of discount codes per order, 2) Enforce a maximum discount percentage, 3) Prevent combining certain discount types, 4) Implement one-time-use validation, and 5) Track discount code usage per user to prevent abuse."
  }
];
