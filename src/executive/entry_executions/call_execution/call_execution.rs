use crate::constructive::entity::account::root_account::root_account::RootAccount;
use crate::constructive::entry::entry_fees::entry_fees::EntryFees;
use crate::constructive::entry::entry_kinds::call::call::Call;
use crate::executive::entry_executions::call_execution::error::call_execution_error::CallExecutionError;
use crate::executive::exec_ctx::exec_ctx::ExecCtx;
use crate::executive::stack::stack_item::StackItem;
use crate::executive::vm::program_execution::caller::Caller;
use crate::executive::vm::program_execution::exec::execute;
use crate::inscriptive::privileges_manager::elements::exemption::exemption::ExemptionSubsidyBreakdown;
use crate::inscriptive::privileges_manager::errors::update_error::PMUpdateAccountError;

impl ExecCtx {
    /// Executes a `Call` entry: validates the caller, charges fees, and runs the
    /// referenced contract method on the VM (which applies the resulting coin/state changes).
    pub async fn execute_call_internal(
        &mut self,
        call: &Call,
        execution_timestamp: u64,
    ) -> Result<EntryFees, CallExecutionError> {
        // 1 Resolve the caller account key.
        let account_key = call.account.account_key();

        // 2 Get params holder for fee parameters.
        let params_holder = {
            let _params_manager = self._params_manager.lock().unwrap();
            _params_manager.get_params_holder()
        };

        // 3 Calculate nominal fees (pre-subsidy): base fee + calldata-bytesize fee.
        let base_fee = params_holder.call_entry_base_fee;
        let calldata_bytesize: u64 = call
            .calldata_elements
            .iter()
            .map(|element| element.into_stack_item().bytes().len() as u64)
            .sum();
        let calldata_fee = calldata_bytesize
            .saturating_mul(params_holder.call_entry_ppm_calldata_bytesize_fee)
            / 1_000_000;
        let fees_pre_subsidy = base_fee
            .checked_add(calldata_fee)
            .ok_or(CallExecutionError::CallFeeOverflow)?;

        // 4 Last activity before this entry (read before `sync_with_registery` bumps it).
        let latest_activity_timestamp = {
            let _registery = self.registery.lock().await;
            _registery
                .get_account_last_activity_timestamp(account_key)
                .unwrap_or(0)
        };

        // 5 Validate the caller `RootAccount` and apply the fee subsidy.
        let (fees_after_subsidy, subsidy_breakdown) = match &call.account {
            RootAccount::UnregisteredRootAccount(_) => {
                return Err(CallExecutionError::UnexpectedUnregisteredRootAccountError);
            }
            RootAccount::RegisteredButUnconfiguredRootAccount(account) => {
                if !account.validate_bls_key() {
                    return Err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountValidateBLSKeyError,
                    );
                }
                if !account.verify_authorization_signature() {
                    return Err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountInvalidAuthorizationSignatureError,
                    );
                }
                account
                    .sync_with_registery(execution_timestamp, &self.registery)
                    .await
                    .map_err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountSyncWithRegisteryError,
                    )?;
                self.apply_subsidy_call(
                    account_key,
                    execution_timestamp,
                    fees_pre_subsidy,
                    latest_activity_timestamp,
                )
                .await?
            }
            RootAccount::RegisteredAndConfiguredRootAccount(account) => {
                account
                    .sync_with_registery(execution_timestamp, &self.registery)
                    .await
                    .map_err(
                        CallExecutionError::RegisteredAndConfiguredRootAccountSyncWithRegisteryError,
                    )?;
                self.apply_subsidy_call(
                    account_key,
                    execution_timestamp,
                    fees_pre_subsidy,
                    latest_activity_timestamp,
                )
                .await?
            }
        };

        // 6 Charge the caller the post-subsidy entry fee.
        {
            let mut _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .account_balance_down(account_key, fees_after_subsidy)
                .map_err(CallExecutionError::CoinManagerAccountBalanceDownError)?;
        }

        // 7 Run the contract method on the VM. The VM applies coin/state changes
        // (e.g. OP_TRANSFER) directly to the managers' deltas.
        let contract_id = call.contract.contract_id();
        let arg_values: Vec<StackItem> = call
            .calldata_elements
            .iter()
            .map(|element| element.into_stack_item())
            .collect();
        let ops_budget = call.ops_budget().unwrap_or(u32::MAX);
        let ops_price = call.ops_price_total();

        execute(
            false,
            Caller::Account(account_key),
            contract_id,
            call.method_index(),
            arg_values,
            execution_timestamp,
            ops_budget,
            ops_price,
            0,
            0,
            &self.state_manager,
            &self.coin_manager,
            &self.registery,
        )
        .await
        .map_err(CallExecutionError::VMExecutionError)?;

        // 8 Return the entry fees.
        Ok(EntryFees::Call {
            base_fee,
            total_pre_subsidy: fees_pre_subsidy,
            subsidy_breakdown,
        })
    }

    /// Applies the fee subsidy for a `Call` entry. Returns the post-subsidy fee
    /// and the breakdown (a zero-subsidy breakdown when the account has no exemptions).
    async fn apply_subsidy_call(
        &self,
        account_key: [u8; 32],
        execution_timestamp: u64,
        fees_pre_subsidy: u64,
        latest_activity_timestamp: u64,
    ) -> Result<(u64, ExemptionSubsidyBreakdown), CallExecutionError> {
        let txfee_exemptions = {
            let _privileges_manager = self.privileges_manager.lock().await;
            _privileges_manager.get_account_txfee_exemptions(account_key)
        };

        // No exemptions: full fee owed at every stage.
        let Some(mut exemptions) = txfee_exemptions else {
            let breakdown = ExemptionSubsidyBreakdown {
                post_periodic_credit_leftover: fees_pre_subsidy,
                post_direct_credit_leftover: fees_pre_subsidy,
                post_discount_leftover: fees_pre_subsidy,
            };
            return Ok((fees_pre_subsidy, breakdown));
        };

        let breakdown = exemptions
            .apply_subsidy(execution_timestamp, latest_activity_timestamp, fees_pre_subsidy)
            .ok_or(CallExecutionError::FailedToApplyFeesSubsidy)?;

        let fees_after_subsidy = breakdown.post_discount_leftover;

        {
            let mut _privileges_manager = self.privileges_manager.lock().await;
            match _privileges_manager
                .set_or_update_account_txfee_exemptions(account_key, exemptions)
            {
                Ok(()) => {}
                Err(PMUpdateAccountError::AccountIsNotPermanentlyRegistered(_)) => {
                    // Ephemeral PM row this batch: no delta write; fee math already used in-memory exemption.
                }
            }
        }

        Ok((fees_after_subsidy, breakdown))
    }
}
