import { useState } from 'react';

/**
 * ApplicationForm Component - LoanShield
 * 
 * Features:
 * - Glassmorphism form design
 * - Real-time validation
 * - Loading and error states
 * - Success modal with decision
 */
export default function ApplicationForm() {
  const [formData, setFormData] = useState({
    name: '',
    pan: '',
    salary: '',
    expense: '',
    loan_amount: '',
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [showResult, setShowResult] = useState(false);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
    // Clear error when user starts typing
    if (error) setError(null);
  };

  const validateForm = () => {
    if (!formData.name.trim()) {
      setError('Name is required');
      return false;
    }
    if (!formData.pan.trim() || formData.pan.length !== 10) {
      setError('Valid 10-digit PAN is required');
      return false;
    }
    if (!formData.salary || parseFloat(formData.salary) <= 0) {
      setError('Valid salary is required');
      return false;
    }
    if (!formData.expense || parseFloat(formData.expense) < 0) {
      setError('Valid monthly expense is required');
      return false;
    }
    if (!formData.loan_amount || parseFloat(formData.loan_amount) <= 0) {
      setError('Valid loan amount is required');
      return false;
    }
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_URL}/api/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Application failed. Please try again.');
      }
      setSuccess(data);
      setShowResult(true);
      // Reset form
      setFormData({
        name: '',
        pan: '',
        salary: '',
        expense: '',
        loan_amount: '',
      });
    } catch (err) {
      const message = err.message || 'Application failed. Please try again.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      pan: '',
      salary: '',
      expense: '',
      loan_amount: '',
    });
    setShowResult(false);
    setSuccess(null);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 py-12 px-4">
      {/* Header */}
      <div className="max-w-md mx-auto mb-8">
        <h1 className="text-3xl font-bold text-cyan-400 text-center mb-2">
          LoanShield
        </h1>
        <p className="text-slate-400 text-center text-sm">
          Quick Loan Application & Decision
        </p>
      </div>

      {/* Form Container */}
      <div className="max-w-md mx-auto">
        {!showResult ? (
          <form
            onSubmit={handleSubmit}
            className="backdrop-blur-xl bg-slate-800/40 border border-slate-700/50 rounded-2xl p-8 shadow-2xl space-y-6"
          >
            {/* Error Message */}
            {error && (
              <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-4 text-red-200 text-sm">
                <div className="flex items-start">
                  <span className="text-lg mr-2">⚠️</span>
                  <span>{error}</span>
                </div>
              </div>
            )}

            {/* Name Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Full Name *
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="John Doe"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 focus:bg-slate-700/70 transition"
                disabled={loading}
              />
            </div>

            {/* PAN Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                PAN (10 digits) *
              </label>
              <input
                type="text"
                name="pan"
                value={formData.pan}
                onChange={handleChange}
                placeholder="AAAPA1234A"
                maxLength="10"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 focus:bg-slate-700/70 transition uppercase"
                disabled={loading}
              />
            </div>

            {/* Annual Salary Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Annual Salary *
              </label>
              <input
                type="number"
                name="salary"
                value={formData.salary}
                onChange={handleChange}
                placeholder="600000"
                min="0"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 focus:bg-slate-700/70 transition"
                disabled={loading}
              />
            </div>

            {/* Monthly Expense Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Monthly Expense *
              </label>
              <input
                type="number"
                name="expense"
                value={formData.expense}
                onChange={handleChange}
                placeholder="25000"
                min="0"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 focus:bg-slate-700/70 transition"
                disabled={loading}
              />
            </div>

            {/* Loan Amount Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Loan Amount *
              </label>
              <input
                type="number"
                name="loan_amount"
                value={formData.loan_amount}
                onChange={handleChange}
                placeholder="500000"
                min="0"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/50 focus:bg-slate-700/70 transition"
                disabled={loading}
              />
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-700 text-slate-900 font-semibold rounded-lg transition-all shadow-lg disabled:shadow-none"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <span className="inline-block w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mr-2" />
                  Processing...
                </span>
              ) : (
                'Get Instant Decision'
              )}
            </button>

            {/* Info Text */}
            <p className="text-xs text-slate-400 text-center">
              ✅ Your application is processed securely with end-to-end encryption
            </p>
          </form>
        ) : (
          /* Result Modal */
          <div className="backdrop-blur-xl bg-slate-800/40 border border-slate-700/50 rounded-2xl p-8 shadow-2xl text-center">
            {success?.status === 'Approved' ? (
              <>
                <div className="text-6xl mb-4">🎉</div>
                <h2 className="text-2xl font-bold text-green-400 mb-2">
                  Congratulations!
                </h2>
                <p className="text-slate-300 mb-6">
                  Your loan application has been <span className="text-green-400 font-semibold">Approved</span>
                </p>

                <div className="bg-slate-700/30 rounded-lg p-6 mb-6 border border-slate-600/50">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-slate-400 text-sm">Credit Tier</p>
                      <p className={`text-xl font-bold ${
                        success?.tier === 'Platinum' ? 'text-cyan-400' :
                        success?.tier === 'Gold' ? 'text-yellow-400' :
                        'text-gray-400'
                      }`}>
                        {success?.tier}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400 text-sm">Status</p>
                      <p className="text-xl font-bold text-green-400">
                        {success?.status}
                      </p>
                    </div>
                  </div>
                </div>

                <p className="text-slate-400 text-sm mb-6">
                  Next steps will be sent to your registered email & SMS
                </p>
              </>
            ) : (
              <>
                <div className="text-6xl mb-4">❌</div>
                <h2 className="text-2xl font-bold text-red-400 mb-2">
                  Application Not Approved
                </h2>
                <p className="text-slate-300 mb-6">
                  Unfortunately your application was <span className="text-red-400 font-semibold">Rejected</span>
                </p>

                <div className="bg-slate-700/30 rounded-lg p-6 mb-6 border border-slate-600/50">
                  <p className="text-slate-400 text-sm mb-2">Reason</p>
                  <p className="text-slate-200">
                    Your debt-to-income ratio exceeds our threshold. Please reapply after 3 months.
                  </p>
                </div>

                <p className="text-slate-400 text-sm">
                  Contact support for alternative options
                </p>
              </>
            )}

            {/* Action Buttons */}
            <div className="space-y-3 mt-8">
              <button
                onClick={resetForm}
                className="w-full py-3 bg-cyan-500 hover:bg-cyan-600 text-slate-900 font-semibold rounded-lg transition-all"
              >
                {success?.status === 'Approved' ? 'Proceed to Disbursal' : 'Apply Again'}
              </button>
              <button
                onClick={() => setShowResult(false)}
                className="w-full py-3 bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold rounded-lg transition-all border border-slate-600/50"
              >
                Back to Form
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
