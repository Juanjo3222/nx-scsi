package main

// key_seed_package capturé du VRAI Nintendo (compte Kazu, MK8DX). Rejoué PAR DÉFAUT quand une
// archive n'a pas encore son propre key_seed : c'est un package RÉEL bien formé -> meilleure chance
// que la console l'accepte au 1er upload. À VALIDER au test console : si la console lie le package
// au challenge (encoded_challenge) ou à un secret de compte, il faudra RE la dérivation de clé.
// Voir memory nextendo-cloud-saves-scsi.
const defaultKeySeed = "AAAAAAAAAAAFAAAAAAAAAN8Gj83Qn41tMgDsLLvaSgjkbNGK5-9yCgdi82XoEcQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXgviOqkE2Eb44n49G6exrjcmBXFjVOBdWpoqC_4f8Lhnk_C4cjmMQth6YH5YaxPXMg6WkyKc-L595IpYJJoJbipU6hsK9QKQNRhdAgpBCn2x1hy0A5WxVOKutP5XIWpuhqmdM_OHoKZvqxkXlez1pkejgW2TWEuPGm9W6pCz5rqM57BOA8i8tljBeNnkRCK9xHDq_kQBv96ebF8w6JFViL4AbzgRqmTYBWbN9paLkCK7IWntMSdtjMxxG8dfEZPtZNpu_X2w9IItwLpJBu5dzMFYwpYqUzXUdaZlrmma69OqJtK2Kcra1SxUtB0usrA_KKxp9vkAyPlHnV5U66mqcMOUZE6Elu50ADn79diSCxMtSECCT5Yne-xmDEgCu_dHkKMqYMlTu-AXTmUQW7jirjStKDW0VN28KPRuHedjEEED7SBk3RSe48guEiNWpIClY9PLtnntQhZ8n7ymAazXeqvK3z0gbHCTEApbzI61YSCBtErMw906NW5-xTrcH1n0="
