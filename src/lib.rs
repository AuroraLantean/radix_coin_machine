use scrypto::prelude::*;

// credit: thanks to Scrypto-Example/regulated-token
// admin, version, withdraw, mint, burn, buy,
blueprint! {
    struct CoinMachine {
        token_vault: Vault,
        auth: Vault,
        collected_xrd: Vault,
        version: u8,
        price: Decimal,
        admin_addr: ResourceAddress,
        fz_addr: ResourceAddress,
    }

    impl CoinMachine {
        pub fn instantiate_regulated_token() -> (ComponentAddress, Bucket, Bucket) {
            // top admin
            let admin_badge: Bucket = ResourceBuilder::new_fungible()
                .divisibility(DIVISIBILITY_NONE)
                .metadata("name", "admin_badge")
                .burnable(rule!(allow_all), LOCKED)
                .initial_supply(1);
            // to withdraw coins
            let wd_badge: Bucket = ResourceBuilder::new_fungible()
                .divisibility(DIVISIBILITY_NONE)
                .metadata("name", "withdraw badge")
                .burnable(rule!(allow_all), LOCKED)
                .initial_supply(1);

            // for minting & withdraw authority
            let auth_badge: Bucket = ResourceBuilder::new_fungible()
                .divisibility(DIVISIBILITY_NONE)
                .metadata("name", "auth_badge")
                .burnable(rule!(allow_all), LOCKED)
                .initial_supply(1);

            // Next we will create our regulated token with an initial fixed supply of 100 and the appropriate permissions
            let token_rule: AccessRule = rule!(
                require(admin_badge.resource_address())
                    || require(auth_badge.resource_address())
            );
            let my_bucket: Bucket = ResourceBuilder::new_fungible()
                .divisibility(DIVISIBILITY_MAXIMUM)
                .metadata("name", "GoldCoin")
                .metadata("symbol", "GLDC")
                .metadata(
                    "version",
                    "version 1 - Fixed supply, withdraw may be restricted",
                )
                .updateable_metadata(token_rule.clone(), token_rule.clone())
                .restrict_withdraw(token_rule.clone(), token_rule.clone())
                .mintable(token_rule.clone(), token_rule.clone())
                .burnable(token_rule.clone(), token_rule.clone())
                .initial_supply(100);

            // Next we need to setup the access rules for the methods of the component
            let method_rule: AccessRules = AccessRules::new()
                .method(
                    "set_withdrawable_vault",
                    rule!(
                        require(admin_badge.resource_address())
                            || require(wd_badge.resource_address())
                    ), AccessRule::DenyAll
                )
                .method(
                    "collect_payments",
                    rule!(require(admin_badge.resource_address())), AccessRule::DenyAll,
                )
                .method(
                    "lift_restriction",
                    rule!(require(admin_badge.resource_address())), AccessRule::DenyAll
                )
                .default(rule!(allow_all), AccessRule::DenyAll);

            let mut component = Self {
                token_vault: Vault::with_bucket(my_bucket),
                auth: Vault::with_bucket(auth_badge),
                collected_xrd: Vault::new(RADIX_TOKEN),
                version: 1,
                price: dec!(32),
                admin_addr: admin_badge.resource_address(),
                fz_addr: wd_badge.resource_address(),
            }
            .instantiate();
            component.add_access_check(method_rule);

            (component.globalize(), admin_badge, wd_badge)
        }

        /// Either the general admin or withdraw badge may be used to seal withdrawing tokens from the vault
        pub fn set_withdrawable_vault(&self, set_frozen: bool) {
            // Note that this operation will fail if the token has reached version 3 and the token behavior has been locked
            let token_rmgr: &mut ResourceManager =
                borrow_resource_manager!(self.token_vault.resource_address());

            self.auth.authorize(|| {
                if set_frozen {
                    token_rmgr.set_withdrawable(rule!(
                        require(self.admin_addr)
                            || require(self.auth.resource_address())
                    ));
                    info!("Token withdraw is now RESTRICTED");
                } else {
                    token_rmgr.set_withdrawable(rule!(allow_all));
                    info!("Token withdraw is lifted");
                }
            })
        }

        /// Permit the proper authority to withdraw our collected XRD
        pub fn collect_payments(&mut self) -> Bucket {
            self.collected_xrd.take_all()
        }

        pub fn lift_restriction(&mut self) {
            // Adding the auth badge to the component auth zone to allow for the operations below
            ComponentAuthZone::push(self.auth.create_proof());

            assert!(self.version <= 2, "Already at version");
            let token_rmgr: &mut ResourceManager =
                borrow_resource_manager!(self.token_vault.resource_address());

            if self.version == 1 {
                // Advance to version 2
                // set token minting to all
                self.version = 2;

                token_rmgr.set_metadata("version".into(), "version 2 - Unlimited supply, may be restricted withdraw".into());

                token_rmgr
                    .set_mintable(rule!(require(self.auth.resource_address())));
                info!("Advanced to version 2");

                // Drop the last added proof to the component auth zone
                ComponentAuthZone::pop().drop();
            } else {
                // Advance to version 3
                // Restricted withdraw and minting will be permanently turned off
                self.version = 3;


                // Update token's metadata to reflect the final version
                token_rmgr.set_metadata("version".into(), "version 3 - Unregulated token, fixed supply".into());

                // Set our behavior appropriately now that the regulated period has ended
                token_rmgr.set_mintable(rule!(deny_all));
                token_rmgr.set_withdrawable(rule!(allow_all));
                token_rmgr.set_updateable_metadata(rule!(deny_all));

                // Permanently prevent the behavior of the token from changing
                token_rmgr.lock_mintable();
                token_rmgr.lock_withdrawable();
                token_rmgr.lock_updateable_metadata();

                // With the resource behavior forever locked, our auth no longer has any use
                // We will burn our auth badge, and the holders of the other badges may burn them at will
                // Our badge has the allows everybody to burn, so there's no need to provide a burning authority

                // Drop the last added proof to the component auth zone
                ComponentAuthZone::pop().drop();

                self.auth.take_all().burn();

                info!("Advanced to version 3");
            }
        }

        /// Buy a quantity of tokens, if the supply on-hand is sufficient, or if current rules permit minting additional supply.
        /// The system will ALWAYS allow buyers to purchase available tokens, even when the token withdraw are frozen
        pub fn buy_token(&mut self, quantity: Decimal, mut payment: Bucket) -> (Bucket, Bucket) {
            assert!(quantity > dec!("0"), "quantity invalid");
            // Adding the auth badge to the component auth zone to allow for the operations below
            ComponentAuthZone::push(self.auth.create_proof());

            // Early birds who buy during version 1 get a discounted rate
            let price: Decimal = if self.version == 1 {
                self.price * dec!("0.99")
            } else {
                self.price
            };

            self.collected_xrd.put(payment.take(price * quantity));

            // Can we fill the desired quantity from current supply?
            let extra_demand = quantity - self.token_vault.amount();
            if extra_demand <= dec!("0") {
                // Take the required quantity, and return it along with any change
                // The token may currently be under restricted withdraw, so we will authorize our withdrawal
                let tokens = self.token_vault.take(quantity);

                // Drop the last added proof to the component auth zone which is the admin badge
                ComponentAuthZone::pop().drop();
                return (tokens, payment);
            } else {
                // We will attempt to mint the shortfall
                // If we are in version 1 or 3, this action will fail, and it would probably be a good idea to tell the user this
                // For the purposes of example, we will blindly attempt to mint
                let mut tokens = borrow_resource_manager!(self.token_vault.resource_address())
                    .mint(extra_demand);

                // Combine the new tokens with whatever was left in supply to meet the full quantity
                let existing_tokens = self.token_vault.take_all();
                tokens.put(existing_tokens);

                // Drop the last added proof to the component auth zone which is the admin badge
                ComponentAuthZone::pop().drop();

                // Return the tokens, along with any change
                return (tokens, payment);
            }
        }

      pub fn get_version(&self) -> u8 {
          info!("Current version is {}", self.version);
          self.version
      }
      pub fn set_version(&mut self, new_version: u8) {
          info!("Current version is {}", self.version);
          assert!(self.version >= 3, "invalid version");
          self.version = new_version;
      }
      pub fn get_price(&self) -> Decimal {
          info!("Current price is {}", self.price);
          self.price
      }
      pub fn set_price(&mut self, new_price: u128) {
          info!("Current price is {}", self.price);
          assert!(new_price <= 0, "invalid price");
          self.price = Decimal::from(new_price);
      }
    }
}
