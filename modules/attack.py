import datetime
from collections import Counter

from mitreattack.stix20 import MitreAttackData
import mitreattack.navlayers as navlayers


class Attack:
    def __init__(self):
        self.source_data = "enterprise-attack.json"
        self.attack_data = MitreAttackData(self.source_data)
        self.techniques = Counter({})

    def get_attack_technique_by_name(self, id):
        try:
            object = self.attack_data.get_object_by_attack_id(id, 'attack-pattern')

            if object is not None:
                result = Counter({id: 1})
                self.techniques = result + self.techniques

            return object
    
        except Exception as e:
            print(f"Failed to get technique {id}: {e}")
    
    def create_nav_layer(self):
        navlayer = navlayers.Layer()
        navlayer.from_dict(dict(name="Microsoft Sentinel - MITRE ATT&CK Navigator Layer", domain="enterprise-attack"))
        navlayer.layer.versions = dict(layer="4.3", attack="14", navigator="4.9.1")
        navlayer.layer.description = f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        navlayer.layer.layout = dict(layout="side",
                                  showID=True,
                                  showName=True,
                                  showAggregateScores=True,
                                  countUnscored=True,
                                  aggregateFunction="sum", # average, sum, max, min
                                  expandedSubtechniques="annotated")  # all, annotated, none
        
        navlayer.layer.gradient = dict(minValue=0, maxValue=20,
                                    colors=["#DAF7A6", "#FFC300", "#FF5733", "#C70039", "#900C3F", "#581845"])
        
        layer_list = []
        for technique in self.techniques:
            layer_list.append(dict(techniqueID=f'{technique}', 
                                   score=self.techniques[technique], 
                                   comment=f'Total number of analytics rules: {self.techniques[technique]}'))

            navlayer.layer.techniques = layer_list
        
        try:
            navlayer.to_file(f"AttackNavLayer_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json")
        except Exception as e:
            print(f"Failed to create navigator layer: {e}")

