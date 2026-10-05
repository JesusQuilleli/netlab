/// <reference types="vitest" />
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// Sin esto cada prueba monta su arbol y lo deja en el documento: la siguiente
// encuentra dos veces los mismos nodos y los `getByText` fallan sin motivo claro.
afterEach(() => cleanup())