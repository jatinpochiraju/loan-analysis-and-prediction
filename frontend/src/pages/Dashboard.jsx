const transactions = [
  {
    id: 1,
    type: 'Application',
    amount: 500000,
    status: 'Approved',
    date: '2026-03-28',
    tier: 'Gold',
  },
  {
    id: 2,
    type: 'EMI Payment',
    amount: 8500,
    status: 'Completed',
    date: '2026-03-25',
  },
  {
    id: 3,
    type: 'EMI Payment',
    amount: 8500,
    status: 'Completed',
    date: '2026-02-25',
  },
];

const creditScore = 745;
const loading = false;

const quickStats = [
  { label: 'Active Loans', value: '2', colorClass: 'text-cyan-400' },
  { label: 'Total Outstanding', value: '4.5L', colorClass: 'text-blue-400' },
  { label: 'EMI Due', value: '8,500', colorClass: 'text-yellow-400' },
  { label: 'Credit Utilization', value: '35%', colorClass: 'text-green-400' },
];

/**
 * Dashboard Component - LoanShield
 * 
 * Features:
 * - Credit Health Gauge (Glassmorphism)
 * - Recent Transactions List
 * - Dark Mode with Slate-900 background and Cyan-400 accents
 * - Responsive grid layout
 */
export default function Dashboard() {
  // Normalize credit score to 0-100 for gauge
  const gaugeValue = (creditScore / 900) * 100;

  // Determine gauge color
  const getGaugeColor = () => {
    if (gaugeValue >= 70) return 'text-green-400';
    if (gaugeValue >= 50) return 'text-cyan-400';
    if (gaugeValue >= 30) return 'text-yellow-400';
    return 'text-red-400';
  };

  // Determine status badge color
  const getStatusColor = (status) => {
    switch (status) {
      case 'Approved':
        return 'bg-green-900 text-green-200';
      case 'Completed':
        return 'bg-cyan-900 text-cyan-200';
      case 'Pending':
        return 'bg-yellow-900 text-yellow-200';
      case 'Rejected':
        return 'bg-red-900 text-red-200';
      default:
        return 'bg-slate-700 text-slate-300';
    }
  };

  const getTierBadgeColor = (tier) => {
    switch (tier) {
      case 'Platinum':
        return 'bg-cyan-500 text-slate-900';
      case 'Gold':
        return 'bg-yellow-500 text-slate-900';
      case 'Silver':
        return 'bg-gray-400 text-slate-900';
      default:
        return 'bg-slate-600 text-slate-200';
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-cyan-400 mb-2">LoanShield</h1>
        <p className="text-slate-400">Your Complete Loan Management Dashboard</p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Credit Health Gauge Card - Glassmorphism */}
        <div className="md:col-span-1 backdrop-blur-xl bg-slate-800/40 border border-slate-700/50 rounded-2xl p-8 shadow-2xl">
          <h2 className="text-lg font-semibold text-cyan-400 mb-6 text-center">
            Credit Health
          </h2>
          
          {/* Circular Gauge */}
          <div className="flex justify-center items-center mb-6">
            <div className="relative w-40 h-40">
              {/* Background circle */}
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="8"
                  className="text-slate-700"
                />
                {/* Progress circle */}
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="8"
                  strokeDasharray={`${(gaugeValue / 100) * 2 * 70 * Math.PI} ${2 * 70 * Math.PI}`}
                  className={`${getGaugeColor()} transition-all duration-500`}
                  strokeLinecap="round"
                />
              </svg>
              {/* Center text */}
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className={`text-4xl font-bold ${getGaugeColor()}`}>
                  {creditScore}
                </div>
                <div className="text-xs text-slate-400">Score</div>
              </div>
            </div>
          </div>

          {/* Score Range Info */}
          <div className="space-y-2 text-sm">
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Excellent</span>
              <span className="text-green-400">800+</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Good</span>
              <span className="text-cyan-400">700-799</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Fair</span>
              <span className="text-yellow-400">600-699</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Poor</span>
              <span className="text-red-400">&lt; 600</span>
            </div>
          </div>
        </div>

        {/* Recent Transactions Card */}
        <div className="md:col-span-2 backdrop-blur-xl bg-slate-800/40 border border-slate-700/50 rounded-2xl p-8 shadow-2xl">
          <h2 className="text-lg font-semibold text-cyan-400 mb-6">
            Recent Transactions
          </h2>

          {loading ? (
            <div className="flex justify-center items-center h-64">
              <div className="animate-spin">
                <div className="w-12 h-12 border-4 border-slate-700 border-t-cyan-400 rounded-full" />
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">
                      Type
                    </th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">
                      Amount
                    </th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">
                      Date
                    </th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">
                      Status
                    </th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">
                      Tier
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((txn) => (
                    <tr key={txn.id} className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                      <td className="py-4 px-4">{txn.type}</td>
                      <td className="py-4 px-4 font-semibold text-cyan-400">
                        {txn.amount.toLocaleString('en-IN')}
                      </td>
                      <td className="py-4 px-4 text-slate-400">{txn.date}</td>
                      <td className="py-4 px-4">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(
                            txn.status
                          )}`}
                        >
                          {txn.status}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        {txn.tier ? (
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-medium ${getTierBadgeColor(
                              txn.tier
                            )}`}
                          >
                            {txn.tier}
                          </span>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-8">
        {quickStats.map((stat, idx) => (
          <div
            key={idx}
            className="backdrop-blur-xl bg-slate-800/40 border border-slate-700/50 rounded-xl p-4 shadow-xl"
          >
            <p className="text-slate-400 text-sm mb-2">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.colorClass}`}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
