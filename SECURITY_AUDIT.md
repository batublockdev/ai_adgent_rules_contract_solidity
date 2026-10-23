# 🔒 Security Audit Report — foundry-account-abstraction

**Fecha:** 2026-10-19  
**Auditor:** Dev Agent (Slither 0.11.6 + análisis manual)  
**Target:** `src/ethereum/MinimalAccount.sol`, `src/ethereum/PayMaster.sol`, `src/libraries/OracleLib.sol`  
**SLOC:** 351 líneas (3 contratos)  
**Tool:** Slither (102 detectores, 71 resultados)

---

## 📊 Resumen

| Severidad | Cantidad | Contratos afectados |
|-----------|----------|---------------------|
| 🔴 High | 4 | MinimalAccount, PayMaster |
| 🟠 Medium | 10 | MinimalAccount, PayMaster, OracleLib |
| 🟡 Low | 6 | MinimalAccount, PayMaster |
| 🔵 Info | 51 | Todos |

---

## 🔴 HIGH — Crítico

### H1. `arbitrary-send-erc20` — PayMaster.postOp
**Contrato:** PayMaster.sol#161-176  
**Issue:** `transferFrom(sender, address(this), tokenCost)` usa `sender` del context sin re-validar. El `sender` viene del `context` decodificado en `postOp`, que fue seteado en `validatePaymasterUserOp`. Si el context se manipula, se podría cobrar USDC de una dirección arbitraria.  
**Impact:** Robo de fondos USDC.  
**Fix:** Re-validar que `sender` == `userOp.sender` en `postOp`, o usar `actualGasCost` para recalcular.

### H2. `arbitrary-send-eth` — MinimalAccount._payPreFunds
**Contrato:** MinimalAccount.sol#454-462  
**Issue:** Envía ETH a `msg.sender` (que es el EntryPoint) con `type(uint256).max` gas. Si el EntryPoint es malicioso o comprometido, podría reentrar.  
**Impact:** Reentrancy via EntryPoint comprometido.  
**Fix:** Usar `gasleft()` en vez de `type(uint256).max`, y verificar que `missingAccountFunds` no exceda el balance del contrato.

### H3. `return-bomb` — MinimalAccount.execute
**Contrato:** MinimalAccount.sol#339-382  
**Issue:** `target.call{gas: gasleft()}` permite que el target retorne datos arbitrariamente grandes, consumiendo todo el gas en el decode de `result`. Un target malicioso podría hacer DoS.  
**Impact:** Denial of Service.  
**Fix:** Limitar el gas del call o usar assembly para limitar el tamaño del returndata.

### H4. `return-bomb` — MinimalAccount._payPreFunds
**Contrato:** MinimalAccount.sol#454-462  
**Issue:** Mismo problema que H3 — `type(uint256).max` gas permite return bombs.  
**Impact:** DoS.  
**Fix:** Mismo que H3.

---

## 🟠 MEDIUM

### M1. `unchecked-transfer` — PayMaster.withdrawTokens
**Contrato:** PayMaster.sol#192-194  
**Issue:** `usdc.transfer(to, amount)` ignora el return value. Si USDC devuelve `false` (no revierte), los tokens se pierden silenciosamente.  
**Fix:** Usar `SafeERC20.safeTransfer()` de OpenZeppelin.

### M2. `unused-return` — PayMaster.getPriceUsd
**Contrato:** PayMaster.sol#220-229  
**Issue:** `staleCheckLastTestRoundData()` retorna 5 valores pero se ignoran 4 (`roundId`, `startedAt`, `updatedAt`, `answeredInRound`). No se valida que `answeredInRound > 0` ni que `updatedAt > 0`.  
**Fix:** Validar `answeredInRound != 0` y `updatedAt != 0` para detectar price feed roto.

### M3. `missing-zero-check` — 3 casos
**Contrato:** MinimalAccount constructor, setAdgent, PayMaster constructor  
**Issue:** No se valida `address(0)` en:
- `constructor(address entryPoint, address adgent)` → `_adgent = adgent`
- `setAdgent(address newAdgent)` → `_adgent = newAdgent`
- `PayMaster constructor` → `gasTokenPriceFeed = _gasTokenPriceFeed`  
**Fix:** Agregar `require(adgent != address(0))` en cada caso.

### M4. `console2.log` en producción
**Contrato:** PayMaster.sol#155-156  
**Issue:** `console2.log` en `validatePaymasterUserOp` gasta gas innecesario y filtra info en mainnet.  
**Fix:** Eliminar antes de deploy.

### M5. `postOp` ignora `actualGasCost`
**Contrato:** PayMaster.sol#161-176  
**Issue:** `postOp` recibe `actualGasCost` pero cobra `tokenCost` pre-calculado con `maxCost`. Si el gas real es menor, el usuario paga de más.  
**Fix:** Recalcular `tokenCost = getPriceUsd(actualGasCost)` en `postOp`.

### M6. `postOp` ignora `PostOpMode`
**Contrato:** PayMaster.sol#161-176  
**Issue:** No diferencia entre `opSucceeded`, `opReverted`, `postOpReverted`. Cobra igual en todos los casos.  
**Fix:** Si `mode == postOpReverted`, no cobrar o reintentar con gas limitado.

### M7. No `ReentrancyGuard` en execute
**Contrato:** MinimalAccount.sol#339-382  
**Issue:** `execute` hace `target.call` externo sin protección reentrancy. El modifier `OnlyEntryPointOrOwner` mitiga pero no previene si el owner es caller.  
**Fix:** Agregar `ReentrancyGuard` de OpenZeppelin.

### M8. `pause()` es toggle sin estado explícito
**Contrato:** MinimalAccount.sol#179-186  
**Issue:** `pause()` togglea `_pause`. No hay `isPaused()` view function. Off-chain no puede saber el estado sin leer storage directamente.  
**Fix:** Agregar `function isPaused() external view returns (bool)`.

### M9. Versiones de pragma inconsistentes
**Contrato:** Todos  
**Issue:** 3 versiones diferentes:
- `MinimalAccount.sol` → `^0.8.24`
- `PayMaster.sol` → `^0.8.20`
- `OracleLib.sol` → `^0.8.18`  
**Fix:** Unificar a `^0.8.24`.

### M10. `getPriceUsd` — sin check de price <= 0
**Contrato:** PayMaster.sol#220-229  
**Issue:** Si el price feed retorna `price = 0` o negativo, `uint256(price)` wrappea a un valor enorme, causando que `tokenCost` sea billones.  
**Fix:** `require(price > 0, "Invalid price")` antes del cálculo.

---

## 🟡 LOW

### L1. `boolean-equal` — comparaciones `== true` / `== false`
**Contrato:** MinimalAccount.sol (6 casos)  
**Issue:** Usar `== true` / `== false` en vez de `!variable` o `variable` directamente.  
**Fix:** Reemplazar `if (_pause == true)` → `if (_pause)`, `if (isAllowedTarget[target] == false)` → `if (!isAllowedTarget[target])`.

### L2. `low-level-calls` — 2 casos
**Contrato:** MinimalAccount.sol#375, #456  
**Issue:** Uso de `.call()` sin checkeo de seguridad adicional.  
**Nota:** Es necesario para la lógica de account abstraction, pero requiere auditoría del flujo.

### L3. `naming-convention` — 4 casos
**Contrato:** MinimalAccount.sol  
**Issue:**
- `i_entryPoint` debería ser `i_entryPoint` (immutable prefix OK pero Slither espera mixedCase)
- `OnlyEntryPoint`, `OnlyEntryPointOrOwner`, `PauseCheck` — modifiers deberían empezar en minúscula  
**Fix:** Renombrar modifiers a `onlyEntryPoint`, `onlyEntryPointOrOwner`, `pauseCheck`.

### L4. `assembly` — 3 casos en MinimalAccount
**Contrato:** MinimalAccount.sol#301, #351, #437  
**Issue:** Uso de assembly para extraer selector y recipient.  
**Nota:** Es necesario para la lógica de offset extraction. Verificar que los offsets sean correctos.

### L5. `timestamp` — OracleLib
**Contrato:** OracleLib.sol#59  
**Issue:** Usa `block.timestamp` para comparar staleness. Mineros pueden manipular timestamp ±15s.  
**Nota:** Aceptable para price feeds con heartbeat > 1h. El TIMEOUT de 3h es seguro.

### L6. No `rescueERC20` — tokens trabados
**Contrato:** MinimalAccount.sol  
**Issue:** Si alguien envía ERC20 al contrato por error, no hay forma de recuperarlos.  
**Fix:** Agregar `rescueERC20(address token, address to, uint256 amount) external onlyOwner`.

---

## 🔵 INFO (no requiere acción inmediata)

- 51 findings informativos (dead code en libs, too-many-digits en OpenZeppelin, etc.)
- 0 issues de optimización
- 0 issues de complex code

---

## 📈 Métricas del análisis

| Métrica | Valor |
|---------|-------|
| Contratos analizados | 23 (3 propios + 20 dependencias) |
| Detectores corridos | 102 |
| Total resultados | 71 |
| SLOC propios | 351 |
| SLOC dependencias | 2,748 |
| Líneas de assembly | 0 (en propios) |
| Issues de optimización | 0 |

| Contrato | Funciones | Features |
|----------|-----------|----------|
| MinimalAccount | 28 | Receive ETH, Send ETH, ecrecover, Assembly |
| PayMaster | 19 | Receive ETH, Send ETH, Tokens interaction |
| OracleLib | 2 | — |

---

## 🎯 Prioridad de fixes

| # | Severidad | Issue | Esfuerzo | Riesgo si no se fixea |
|---|-----------|-------|----------|----------------------|
| H1 | 🔴 | postOp arbitrary transferFrom | 30min | Robo de USDC |
| H2 | 🔴 | _payPreFunds gas ilimitado | 5min | Reentrancy |
| H3 | 🔴 | execute return bomb | 15min | DoS |
| M1 | 🟠 | withdrawTokens unchecked transfer | 5min | Tokens perdidos |
| M3 | 🟠 | Missing zero-check (3 casos) | 10min | Config rota |
| M5 | 🟠 | postOp ignora actualGasCost | 30min | Overcharge |
| M6 | 🟠 | postOp ignora PostOpMode | 30min | Cobro incorrecto |
| M7 | 🟠 | ReentrancyGuard | 15min | Reentrancy |
| M10 | 🟠 | getPriceUsd sin price > 0 | 5min | tokenCost billones |
| M4 | 🟠 | console2.log | 2min | Gas + info leak |
| M9 | 🟠 | Pragma unificación | 5min | Compatibilidad |
| L1 | 🟡 | Boolean comparisons | 10min | Style |
| L3 | 🟡 | Naming conventions | 10min | Style |
| L6 | 🟡 | rescueERC20 | 15min | Tokens trabados |
| M8 | 🟠 | isPaused() view | 5min | UX |

---

*Reporte generado con Slither 0.11.6 + análisis manual. 102 detectores, 71 resultados.*