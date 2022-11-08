// ------------------------------------------------------------------------------------------
// CREATE TAGS (Automation)
// ------------------------------------------------------------------------------------------

USE ROLE tag_admin;
USE SCHEMA governance.tags;
CREATE OR REPLACE TAG governance.tags.data_protection_tags ALLOWED_VALUES 'ssn', 'email';
 
SHOW TAGS IN DATABASE GOVERNANCE;

// ------------------------------------------------------------------------------------------
// CREATE MASKING POLICIES 
// ------------------------------------------------------------------------------------------


USE ROLE masking_admin;
USE SCHEMA governance.masking_policies;

CREATE OR REPLACE MASKING POLICY general_mask_tags_string AS (val STRING) RETURNS STRING ->
  CASE
  	WHEN current_role() in ('ACCOUNTADMIN') THEN val
    WHEN EXISTS (
        SELECT 1 FROM governance.entitlements.masking_protection_role
            WHERE system$get_tag_on_current_column('tags.DATA_PROTECTION_TAGS') = governance.entitlements.masking_protection_role.tag_value AND 
                governance.entitlements.masking_protection_role.role = current_role()
    ) THEN val    
    ELSE '****//MASKED'
  END;

CREATE OR REPLACE MASKING POLICY general_mask_tags_number AS (val NUMBER) RETURNS NUMBER ->
  CASE
  	WHEN current_role() in ('ACCOUNTADMIN') THEN val
    WHEN EXISTS (
        SELECT 1 FROM governance.entitlements.masking_protection_role
            WHERE system$get_tag_on_current_column('tags.DATA_PROTECTION_TAGS') = governance.entitlements.masking_protection_role.tag_value AND 
                governance.entitlements.masking_protection_role.role = current_role()
    ) THEN val    
    ELSE '-1'
  END;

// ------------------------------------------------------------------------------------------
// APPLY MASKING POLICIES TO A TAG
// ------------------------------------------------------------------------------------------


ALTER TAG governance.tags.data_protection_tags SET 
    MASKING POLICY GENERAL_MASK_TAGS_NUMBER, 
    MASKING POLICY GENERAL_MASK_TAGS_STRING;

// ------------------------------------------------------------------------------------------
// APPLY THE TAG WITH A MASKING POLICY TO A COLUMN
// ------------------------------------------------------------------------------------------


ALTER TABLE SP500.CONSUMPTION_ZONE.STOCKS_DIM modify column
  CLOSE set tag governance.tags.data_protection_tags = 'email',
  SYMBOL set tag governance.tags.data_protection_tags = 'ssn';  
  
// ------------------------------------------------------------------------------------------
// CREATE A ROW ACCESS POLICY
// ------------------------------------------------------------------------------------------

USE ROLE ROW_ACCESS_ADMIN;
USE SCHEMA row_access_policies;



CREATE OR REPLACE ROW ACCESS POLICY role_policy as (sector_value varchar) returns boolean ->
    'ACCOUNTADMIN' = current_role()
    OR is_role_in_session('WITHOUT_ROW_ACCESS')
    OR EXISTS (
        SELECT 1 FROM governance.entitlements.role_sector_mapping
            WHERE ACCESSIBLE_TO_ROLE = current_role() AND
                sector_value = governance.entitlements.role_sector_mapping.sector
    );

// ------------------------------------------------------------------------------------------
// APPLY THE ROW ACCESS LEVEL TO A COLUMN
// ------------------------------------------------------------------------------------------

ALTER TABLE SP500.CONSUMPTION_ZONE.STOCKS_DIM ADD ROW ACCESS POLICY role_policy on (sector);

// ------------------------------------------------------------------------------------------
// SHOW ENTITLEMENTS TABLE
// ------------------------------------------------------------------------------------------

USE ROLE entitlement_admin;
INSERT INTO governance.entitlements.masking_protection_role (role, tag_value ) VALUES ('ROLE_A', 'email');
INSERT INTO governance.entitlements.masking_protection_role (role, tag_value ) VALUES ('ROLE_B', 'ssn');

INSERT INTO governance.entitlements.role_sector_mapping (accessible_to_role, sector) VALUES ('ROLE_A', 'Healthcare');
INSERT INTO governance.entitlements.role_sector_mapping (accessible_to_role, sector) VALUES ('ROLE_A', 'Utilities');


SELECT * FROM governance.entitlements.masking_protection_role;
SELECT * FROM governance.entitlements.role_sector_mapping;
  

// ----------------------------------------------------------------------------------------------------------
// VERIFY THE ACCESS FOR ROLE_A: COLUMN SYMBOL MASKED, COLUMN CLOSE UNMASKED AND ONLY GETS HEALTHCARE SECTOR
// -----------------------------------------------------------------------------------------------------------

USE ROLE role_a; // Unmask close & Healthcare sector

SELECT operationdate,symbol,close,sector 
    FROM sp500.consumption_zone.stocks_dim 
    LIMIT 100;

SELECT sector,COUNT(SECTOR) 
    FROM sp500.consumption_zone.stocks_dim 
    GROUP BY SECTOR ;

// ----------------------------------------------------------------------------------------------------------
// VERIFY THE ACCESS FOR ROLE_B: COLUMN SYMBOL UNMASKED, COLUMN CLOSE MASKED AND  GETS ALL SECTORS
// -----------------------------------------------------------------------------------------------------------


USE ROLE role_b; // Unmask symbol & All sector

SELECT current_available_roles();



SELECT operationdate,symbol,close,sector 
    FROM sp500.consumption_zone.stocks_dim 
    LIMIT 100;

SELECT sector,COUNT(SECTOR) 
    FROM sp500.consumption_zone.stocks_dim 
    GROUP BY SECTOR ;

