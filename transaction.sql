INSERT INTO public."transaction" (transaction_id,transaction_type,transaction_date,transaction_ammount,transaction_description,transaction_sender,transaction_sender_branch,branch_id,account_id) VALUES
	 (1,'save','2021-01-18 00:00:00',300000,NULL,NULL,NULL,'0001',312001),
	 (2,'save','2021-02-11 00:00:00',240000,NULL,NULL,NULL,'0002',312002),
	 (3,'save','2021-01-19 00:00:00',640000,NULL,NULL,NULL,'0003',312003),
	 (4,'save','2021-01-29 00:00:00',250000,NULL,NULL,NULL,'0004',312004),
	 (5,'transfer','2021-02-27 00:00:00',175000,NULL,312003,'0003','0001',312001),
	 (6,'transfer','2021-02-21 00:00:00',100000,NULL,312001,'0001','0004',312004),
	 (7,'transfer','2021-02-22 00:00:00',100000,NULL,312001,'0001','0002',312002),
	 (8,'transfer','2021-02-22 00:00:00',120000,NULL,312001,'0001','0003',312003),
	 (9,'withdraw','2021-03-21 00:00:00',50000,NULL,NULL,NULL,'0001',312001),
	 (10,'withdraw','2021-03-11 00:00:00',150000,NULL,NULL,NULL,'0003',312003);
INSERT INTO public."transaction" (transaction_id,transaction_type,transaction_date,transaction_ammount,transaction_description,transaction_sender,transaction_sender_branch,branch_id,account_id) VALUES
	 (11,'transfer','2021-04-22 00:00:00',15000,NULL,312002,'0002','0003',312003),
	 (12,'save','2020-04-21 00:00:00',750000,NULL,NULL,NULL,'0001',312005);