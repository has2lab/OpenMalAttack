import torch
import torch.nn.functional as F


def PGD(x, y, net, attack_steps=250, attack_lr=0.01, random_init=True, target=None, clamp=(0, 1)):
    """
    :param x: Inputs to perturb
    :param y: Corresponding ground-truth labels
    :param net: Network to attack
    :param attack_steps: Number of attack iterations
    :param attack_lr: Learning rate of attacker
    :param random_init: If true, uses random initialization
    :param target: If not None, attacks to the chosen class. Dimension of target should be same as labels
    :return:
    """
    attack_eps = 0.3
    x_adv = x.clone()

    if random_init:
        # Flag to use random initialization
        x_adv = x_adv + (torch.rand(x.size(), dtype=x.dtype, device=x.device) - 0.5) * 2 * attack_eps

    for i in range(attack_steps):
        x_adv.requires_grad = True

        net.zero_grad()
        logits = net(x_adv)

        if target is None:
            # Untargeted attacks - gradient ascent
            loss = F.cross_entropy(logits, y)
            loss.backward()
            grad = x_adv.grad.detach()
            grad = grad.sign()
            x_adv = x_adv + attack_lr * grad

        else:
            # Targeted attacks - gradient descent
            assert target.size() == y.size()
            loss = F.cross_entropy(logits, target)
            loss.backward()
            grad = x_adv.grad.detach()
            grad = grad.sign()
            x_adv = x_adv - attack_lr * grad

        # Projection
        x_adv = x + torch.clamp(x_adv - x, min=-attack_eps, max=attack_eps)
        x_adv = x_adv.detach()
        x_adv = torch.clamp(x_adv, *clamp)

    return x_adv
