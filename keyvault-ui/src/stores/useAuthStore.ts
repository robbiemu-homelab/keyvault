import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  apiKey: string;
  projectKey: string;
  setApiKey: (key: string) => void;
  setProjectKey: (key: string) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      apiKey: '',
      projectKey: '',
      setApiKey: (apiKey) => set({ apiKey }),
      setProjectKey: (projectKey) => set({ projectKey }),
    }),
    {
      name: 'keyvault-auth', // localStorage key
      partialize: (state) => ({ apiKey: state.apiKey }), // Only persist apiKey
    }
  )
);
