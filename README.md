# BlindingSignature
L'objectif du projet etait d’implémenter un système de signature aveugle en utilisant Java Cryptography combiné avec les APIs du provider Bouncy Castle.
La signature aveugle consiste à se faire signer un message ou un document sans que l’autorité signataire ne puisse prendre
connaissance du contenu au moment de la signature.
Le propriétaire du document et l’autorité signature sont deux entités distinctes.
Ce type de signature est souvent utilisé dans les applications telles que le vote
électronique, la monnaie numérique.
La vérification de la signature peut être faite publiquement à partir du message,
document original.
